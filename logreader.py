#!/usr/bin/env python3
"""logreader: pass list of unified_support logs as a parameter."""

# Copyright 2024 Pexip AS
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import argparse
import ast
import bisect
import fileinput
import json
import os
import re
import sys
from datetime import datetime, timedelta
from time import strftime, gmtime
from operator import attrgetter, itemgetter
from urllib.parse import urlparse, parse_qs
from collections import defaultdict

try:
    from si.platform.lxml import etree
except ImportError:
    from lxml import etree

show_ports = False
no_bfcp = False
no_ice = False
no_media = False
no_vsr = False
no_audio_msi = False
call_map = {}
conversation_map = defaultdict(set)
quot_end = re.compile(r'(?<!\\)"(?:\s+|$)')
path_element = re.compile(r"([A-Z]+)\((.+)\)")
h323_vendor = re.compile(r"\(([0-9L\s,]+)\) \((.+)\)")
bfcp_num_field = re.compile(r"(\d+)[,)]")
h239_types = {
    "3": "presentationTokenRequest",
    "4": "presentationTokenResponse",
    "5": "presentationTokenRelease",
    "6": "presentationTokenIndicateOwner",
}


def stable_call_quality_to_text(quality_report, stream_type):
    qualities = {0: "Unknown", 1: "Good", 2: "Okay", 3: "Bad", 4: "Terrible"}
    return qualities.get(quality_report.get(stream_type, 0), "Unknown")


class AdminFields:
    def __init__(self):
        self.fields = defaultdict(set)

    def update(self, fields):
        for key, value in fields.items():
            self.fields[key].add(value)

    def get_list(self, key, default=None):
        if key not in self.fields:
            if default is None:
                return []

            return default

        return list(self.fields[key])

    def get(self, key, default=None):
        if key not in self.fields:
            return default

        value = list(self.fields[key])
        if len(value) > 1:
            return ", ".join(value)

        return value[0]


class Call:
    def __init__(self, callid):
        self.callid = callid
        # signaling node
        self.msgs = []
        self.admin = AdminFields()
        self.media_host = "Unknown"
        self.signaling_host = "Unknown"
        self.external_participant_count = 0

    @property
    def start_tts(self):
        return self.msgs[0].tts

    @property
    def end_tts(self):
        return self.msgs[-1].tts

    @property
    def start(self):
        return datetime.strptime(self.start_tts, "%Y-%m-%d %H:%M:%S,%f")

    @property
    def end(self):
        return datetime.strptime(self.end_tts, "%Y-%m-%d %H:%M:%S,%f")

    @property
    def duration(self):
        return str(self.end - self.start)

    def add_msg(self, msg):
        if isinstance(msg, AdminMessage):
            msg.fields = {k: v for k, v in msg.fields.items() if v}
            self.admin.update(msg.fields)
        else:
            self.msgs.append(msg)

    def add_tcpmsgs(self, tcpmsgs):
        tuples = set()
        transport = "5060"
        for msg in self.msgs:
            if isinstance(msg, SIPMessage):
                tuples.add(msg.local + msg.remote)
                if msg.proto == "TLS":
                    transport = "5061"
            elif isinstance(msg, DNSResponse) and msg.result:
                tuples.add((msg.result, ""))
        if not tuples:
            return

        msgs = set()
        for key in tuples:
            if len(key) == 4:
                msgs.update(set(tcpmsgs.get("%s:%s.%s:%s" % key, [])))
            elif len(key) == 2:
                remote = f"{key[0]}:{transport}"
                for tcp_key in tcpmsgs.keys():
                    if tcp_key.endswith(remote):
                        msgs.update(set(tcpmsgs[tcp_key]))
        msgs = list(msgs)
        msgs.sort()

        slack = timedelta(seconds=35)
        for msg in msgs:
            if self.start - slack < msg.timestamp < self.end + slack:
                bisect.insort(self.msgs, msg)

    def tidy_msgs(self):
        # Ensure the list of messages is sorted before we start tidying
        self.msgs.sort()

        # Final call before any printing
        proxied = False
        for msg in self.msgs:
            if isinstance(msg, ICEMessage):
                if msg.getMediaType() == "proxy-external":
                    proxied = True
                    break
        if proxied:
            for i in range(len(self.msgs) - 1, -1, -1):
                if isinstance(self.msgs[i], ICEMessage):
                    if self.msgs[i].getMediaType() != "proxy-external":
                        del self.msgs[i]

        #
        # Some dictionaries for accumulating participant/tags/ssrc data for Teams calls
        #

        # Map tags allocated by the MCU to participant IDs from the Connector
        tag_participant_map = {"4294967295": "STOP", "4294967294": "ANY"}

        # Map Connector participant IDs to participant display names or aliases
        participant_name_map = {"STOP": "STOP", "ANY": "ANY"}

        # Map SSRCs to prettified stream names
        ssrc_stream_id_map = {}

        # Map stream ids to participant names
        stream_id_participant_name_map = {11: "Presentation"}

        # Tidy up primarily aimed at Teams messages
        for msg in self.msgs:
            # These messages can use accumulated information from other messaging to
            # provide better context.
            if isinstance(msg, (VSRMessage, ExternalSpeakerMessage, RESTMessage)):
                msg.participant_name_map = participant_name_map
                msg.tag_participant_map = tag_participant_map
                msg.ssrc_stream_id_map = ssrc_stream_id_map

            if isinstance(msg, (VSRMessage, LostIncomingVideoMessage)):
                msg.stream_id_participant_name_map = stream_id_participant_name_map

            if isinstance(msg, RESTMessage):
                if msg.method == "ROSTER":
                    if isinstance(msg.payload, dict):
                        # Pull out roster add request information from the Connector and populate
                        # the mapping of participant id -> participant name / alias
                        roster_add_requests = msg.payload["roster"]["add"]
                        roster_delete_requests = msg.payload["roster"]["delete"]

                        # Give the message the current participant count
                        msg.external_participant_count = self.external_participant_count

                        self.external_participant_count -= len(roster_delete_requests)
                        for roster_add_request in roster_add_requests:
                            participant_name_map[roster_add_request["id"]] = (
                                roster_add_request["display"]
                                or roster_add_request["alias"]
                            )
                    elif isinstance(msg.payload, list):
                        # Pull out roster add response information from the MCU and populate
                        # the tag -> participant ID map
                        for roster_response in msg.payload:
                            tag_participant_map[
                                str(roster_response["tag"])
                            ] = roster_response["id"]

                        # Increment the participant count when the response is sent
                        self.external_participant_count += len(msg.payload)
                        msg.external_participant_count = self.external_participant_count

                elif msg.method in ["REQUEST_TOKEN", "TEAMS_CONFIGURE_MEDIA"]:
                    if not isinstance(msg.payload, dict):
                        continue
                    media = msg.payload.get("media")
                    if not media:
                        continue
                    # Pull out the media information from the Connector and populate
                    # the ssrc -> stream prettification map
                    for i, video_ssrc in enumerate(media["video"]["ssrcs"], 1):
                        ssrc_stream_id_map[video_ssrc] = (i, f"Stream {i}")
                    ssrc_stream_id_map[media["presentation"]["ssrc"]] = (
                        11,
                        "Presentation",
                    )
            elif isinstance(msg, TeamsMessage):
                if msg.method == "INCOMING":
                    media = msg.payload.get("media")
                    if not media:
                        continue
                    # Pull out the media request information from the MCU and populate
                    # the ssrc -> stream prettification map
                    for i, video_ssrc in enumerate(media["video"]["ssrcs"], 1):
                        ssrc_stream_id_map[video_ssrc] = (i, f"Stream {i}")
                    ssrc_stream_id_map[media["presentation"]["ssrc"]] = (
                        11,
                        "Presentation",
                    )

        prev_vsr_sent = None
        prev_vsr_rcvd = None
        prev_ice = {}
        to_remove = []
        for i in range(len(self.msgs)):  # pylint: disable=consider-using-enumerate
            msg = self.msgs[i]
            if isinstance(msg, ICEMessage):
                if msg.getKey() not in prev_ice:
                    prev_ice[msg.getKey()] = msg
                    continue

                if msg == prev_ice[msg.getKey()]:
                    to_remove.append(i)
                else:
                    prev_ice[msg.getKey()] = msg
            elif isinstance(msg, VSRMessage):
                if "Sent" in msg.msg:
                    if prev_vsr_sent and prev_vsr_sent == msg:
                        to_remove.append(i)
                    else:
                        prev_vsr_sent = msg
                elif "Received" in msg.msg:
                    if prev_vsr_rcvd and prev_vsr_rcvd == msg:
                        to_remove.append(i)
                    else:
                        prev_vsr_rcvd = msg
        for i in reversed(to_remove):
            del self.msgs[i]

        gmsrequests = {}
        for msg in self.msgs:
            if not isinstance(msg, GMSMessage):
                continue

            if msg.msg == "Sending GMS request":
                gmsrequests[msg.request_id] = msg
            elif msg.msg == "Received GMS response":
                if msg.request_id in gmsrequests:
                    msg.request = gmsrequests[msg.request_id]
                    gmsrequests[msg.request_id].response = msg
            else:
                if msg.request_id in gmsrequests:
                    msg.request = gmsrequests[msg.request_id]

        self.msgs.sort()

    def get_init(self):
        for msg in self.msgs:
            if msg.is_init():
                return msg
        return None

    def get_vendor(self):
        vendor = self.admin.get("vendor")
        if vendor:
            groups = h323_vendor.match(vendor)
            return groups.group(2) if groups else vendor
        for msg in self.msgs:
            if msg.user_agent and not msg.out:
                return msg.user_agent
        return "Unknown"

    def to_text(self, fp):
        init_msg = self.get_init()
        fp.write(f"\n\nCall-ID: {self.callid}\n")
        conversation_id = self.admin.get("conversation-id")
        participant_id = self.admin.get("participant-id")
        if conversation_id and set(self.admin.get_list("protocol", ["Unknown"])) & {
            "MSSIP",
            "API",
            "WebRTC",
            "SIP",
        }:
            fp.write(f"Conversation-ID: {conversation_id}\n")
        if participant_id:
            fp.write(f"Participant-ID: {participant_id}\n")
        related_participants = conversation_map[conversation_id] - set(
            self.admin.get_list("participant-id", [])
        )
        if related_participants:
            fp.write(
                "Related Participants: {}\n".format(", ".join(related_participants))
            )
        if self.admin.get("service-type"):
            fp.write(
                "Service: {} ({}) / Protocol: {}\n".format(
                    self.admin.get("service-type"),
                    self.admin.get("conference"),
                    self.admin.get("protocol", "Unknown"),
                )
            )
        if not isinstance(init_msg, H245Message):
            fp.write(f"From: {init_msg.from_addr} / To: {init_msg.to_addr}")
            if self.admin.get("direction"):
                fp.write(" / Direction: {}".format(self.admin.get("direction")))
            fp.write("\n")
        fp.write(
            "Start: {} / End: {} / Duration: {}\n".format(
                self.start_tts, self.end_tts, self.duration
            )
        )
        fp.write(
            "Signalling-Node: {} ({}) [Location: {}] / Media-Node: {} ({}) [Location: {}]".format(
                self.admin.get("signaling-node", "Unknown"),
                self.signaling_host,
                self.admin.get("signaling-location", "Unknown"),
                self.admin.get("media-node", "Unknown"),
                self.media_host,
                self.admin.get("location", "Unknown"),
            )
        )
        if self.admin.get("proxy-node"):
            fp.write(
                " / Proxy-Node: {} [Location: {}]".format(
                    self.admin.get("proxy-node"),
                    self.admin.get("proxy-location", "Unknown"),
                )
            )
        fp.write("\n")

        fp.write(f"Remote Vendor: {self.get_vendor()}\n")
        if self.admin.get("detail"):
            fp.write("Disconnect Reason: {}\n".format(self.admin.get("detail")))
        for msg in self.msgs:
            if isinstance(msg, BFCPMessage) and no_bfcp:
                continue
            if isinstance(msg, ICEMessage) and (
                no_ice or self.admin.get("protocol", "Unknown") == "TEAMS"
            ):
                continue
            if isinstance(msg, MediaMessage) and no_media:
                continue
            if isinstance(msg, VSRMessage) and no_vsr:
                continue
            if isinstance(msg, ExternalSpeakerMessage) and no_audio_msi:
                continue
            fp.write(f"{msg}\n")


class Message:
    """Base class for all messages."""

    def __init__(self, tts):
        self.tts = tts
        # call id
        self.call = None
        self.user_agent = None

    def __lt__(self, other):
        if not isinstance(other, Message):
            return super().__lt__(other)
        return self.tts < other.tts

    def __gt__(self, other):
        if not isinstance(other, Message):
            return super().__gt__(other)
        return self.tts > other.tts

    def __eq__(self, other):
        if not isinstance(other, Message):
            return super().__eq__(other)
        return self.tts == other.tts

    def __hash__(self):
        return hash(self.tts)

    def is_init(self):  # pylint: disable=no-self-use
        return False


class SIPMessageFragment(Message):
    def __init__(
        self,
        host,
        detail,
        src,
        dst,
        transport,
        tts,
        fragment_id,
        fragment_number,
        fragment_total,
        out,
    ):
        Message.__init__(self, tts)
        self.host = host
        self.detail = detail
        self.src = src
        self.dst = dst
        self.proto = transport
        self.out = out
        self.fragment_id = fragment_id
        self.fragment_number = int(fragment_number)
        self.fragment_total = int(fragment_total)


class SIPMessage(Message):
    def __init__(self, msg, src, dst, transport, tts, out):
        Message.__init__(self, tts)
        lines = msg.split("^M")
        self.method = lines.pop(0)
        self.fields = {}
        self.src = src
        self.dst = dst
        self.proto = transport
        self.out = out
        self.aux = []
        self.xml = ""
        self.missing_fragments = 0

        client_ip = None
        bandwidth = None
        m_line = ""
        crypto = False
        transport = None
        for line in lines:
            if line.startswith("<") or self.xml:
                self.xml += line
            elif ": " in line:
                (key, val) = line.split(": ", 1)

                if key.lower() in self.fields:
                    self.fields[key.lower()] += "," + val
                else:
                    self.fields[key.lower()] = val
            elif len(line) > 1 and line[1] == "=":
                if line.startswith("m="):
                    if m_line:
                        self.aux.append(m_line)
                    cols = line.split()
                    m_line = " ".join(cols[:2])
                    try:
                        transport = cols[2]
                    except IndexError:
                        m_line += " (truncated)"
                elif line.startswith("c=") and not client_ip:
                    client_ip = line.strip()
                elif line.startswith("b=AS") and not bandwidth:
                    bandwidth = line.strip()
                elif line == "a=content:slides":
                    m_line += " (slides)"
                elif line.startswith("a=floorctrl:"):
                    try:
                        m_line += " ({} {})".format(transport, line.split(":", 1)[1])
                    except IndexError:
                        m_line += " (truncated)"
                elif line.startswith("a=crypto"):
                    crypto = True
                elif line in ("a=sendonly", "a=recvonly", "a=inactive"):
                    m_line += f" [{line[2:]}]"

        if m_line:
            self.aux.append(m_line)
            self.aux.append(f"[Crypto: {crypto}]")

        if bandwidth:
            self.aux.insert(0, bandwidth)
        if client_ip:
            self.aux.insert(0, client_ip)

        self.call = self.fields.get("call-id", None)
        self.from_addr = self.fields.get("from", "")
        if ">" in self.from_addr:
            self.from_addr = self.from_addr[: self.from_addr.find(">") + 1]
        self.to_addr = self.fields.get("to", "")
        if ">" in self.to_addr:
            self.to_addr = self.to_addr[: self.to_addr.find(">") + 1]
        if "user-agent" in self.fields:
            self.user_agent = self.fields["user-agent"]

    def __str__(self):
        if self.out:
            ret = f"{self.tts} {self.src[0]} -> {self.dst[0]} "
        else:
            ret = f"{self.tts} {self.dst[0]} <- {self.src[0]} "
        ret += f"[{self.proto}] "
        indent = len(ret)

        if self.method.startswith("SIP/2.0"):
            ret += "{} ({})".format(
                self.method[8:], self.fields.get("cseq", self.method.split()[0])
            )
        else:
            ret += self.fields.get("cseq", self.method.split()[0])

        if self.missing_fragments:
            ret += f" (missing {self.missing_fragments} fragment(s))"

        if "content-type" in self.fields:
            if self.fields["content-type"].lower() == "application/sdp":
                ret += " + SDP"
            elif (
                self.fields["content-type"].lower() == "application/conference-info+xml"
            ):
                try:
                    root = etree.fromstring(self.xml)  # noqa: S320
                    users = root.find("{urn:ietf:params:xml:ns:conference-info}users")
                    if users is not None:
                        users = users.findall(
                            "{urn:ietf:params:xml:ns:conference-info}user"
                        )
                        for user in users:
                            # alias = user.find('{urn:ietf:params:xml:ns:conference-info}display-text')
                            # if alias:
                            #     alias = alias.text
                            # else:
                            #     alias = user.attrib['entity']
                            ret += "\n" + (" " * indent)
                            ret += "- " if user.attrib["state"] == "deleted" else "+ "
                            ret += user.attrib["entity"]
                except (SyntaxError, ValueError) as pe:
                    if self.missing_fragments == 0:
                        ret += f" Parse Error ({pe})"

        if "reason" in self.fields:
            ret += " (" + self.fields["reason"] + ")"

        ms_diagnostics = None
        if "ms-client-diagnostics" in self.fields:
            ms_diagnostics = self.fields["ms-client-diagnostics"]
        elif "ms-diagnostics-public" in self.fields:
            ms_diagnostics = self.fields["ms-diagnostics-public"]

        if ms_diagnostics:
            start = ms_diagnostics.find('reason="')
            if start > -1:
                start += 8
                end = ms_diagnostics.find('"', start)
                if end > -1:
                    ret += f" (Reason: {ms_diagnostics[start:end]})"

        if self.aux and show_ports:
            ret += "\n" + (" " * indent)
            if len(self.aux) > 4:
                ret += "; ".join(self.aux[:4])
                ret += ";\n" + (" " * indent)
                ret += "; ".join(self.aux[4:])
            else:
                ret += "; ".join(self.aux)

        return ret

    @property
    def local(self):
        return self.src if self.out else self.dst

    @property
    def remote(self):
        return self.dst if self.out else self.src

    def is_init(self):
        return self.method.startswith("INVITE") or (
            self.method.startswith("SUBSCRIBE") and "focus:id:" in self.to_addr
        )


class SIPSummaryMessage(Message):
    def __init__(self, fields, src, dst, transport, tts, out):
        Message.__init__(self, tts)
        self.fields = fields
        self.src = src
        self.dst = dst
        self.proto = transport
        self.out = out
        self.method = self.fields["method"]
        self.call = self.fields["call-id"]
        self.from_addr = self.fields["from"]
        self.to_addr = self.fields["to"]

    def __str__(self):
        if self.out:
            ret = f"{self.tts} {self.src[0]} -> {self.dst[0]} "
        else:
            ret = f"{self.tts} {self.dst[0]} <- {self.src[0]} "

        ret += f"[{self.proto}] "
        ret += "{} {}".format(self.fields["cseq"], self.fields["method"])

        if "status-code" in self.fields:
            ret += " ({})".format(self.fields["status-code"])

        return ret

    def is_init(self):
        return False


class WebRTCMessage(Message):
    def __init__(self, msg, src, dst, tts, conf, uuid, out):
        Message.__init__(self, tts)
        self.src = src
        self.dst = dst
        self.out = out
        self.call = uuid
        self.from_addr = src
        self.to_addr = conf
        self.aux = []

        lines = msg.split("^M")
        self.payload = ast.literal_eval(lines[0])

        self.method = self.payload["type"].upper()

        if "sdp" in self.payload:
            lines = self.payload["sdp"].split("\r\n")
            client_ip = None
            bandwidth = None
            for line in lines:
                if len(line) > 1 and line[1] == "=":
                    if line.startswith("m="):
                        cols = line.split()
                        self.aux.append(" ".join(cols[:2]))
                    elif line.startswith("c=") and not client_ip:
                        client_ip = line.strip()
                    elif line.startswith("b=AS") and not bandwidth:
                        bandwidth = line.strip()

            if bandwidth:
                self.aux.insert(0, bandwidth)
            if client_ip:
                self.aux.insert(0, client_ip)

        if self.method == "CONFIG" and "name" in self.payload:
            self.from_addr += " ({})".format(self.payload["name"])

    def __str__(self):
        if self.out:
            ret = f"{self.tts} {self.src[0]} -> {self.dst[0]} "
        else:
            ret = f"{self.tts} {self.dst[0]} <- {self.src[0]} "
        indent = len(ret)

        ret += self.method

        if "sdp" in self.payload:
            ret += " + SDP"

        if "reason" in self.payload:
            ret += " (Reason: {})".format(self.payload["reason"])

        if self.aux and show_ports:
            ret += "\n" + (" " * indent)
            ret += "; ".join(self.aux)

        return ret

    def is_init(self):
        return self.method == "CONFIG" and self.from_addr


class RESTMessage(Message):
    def __init__(self, request, src, dst, tts, uuid, detail, out):
        Message.__init__(self, tts)
        self.src = src
        self.dst = dst
        self.out = out
        self.call = uuid
        self.from_addr = dst
        self.participant_name_map = None
        self.tag_participant_map = None
        self.ssrc_stream_id_map = None
        self.external_participant_count = 0

        urlpath = list(filter(None, urlparse(request).path.split("/")))
        self.to_addr = urlpath[urlpath.index("conferences") + 1]
        self.method = urlpath[-1].upper()

        try:
            self.method_path = (
                "BREAKOUTS/" + urlpath[urlpath.index("breakouts") + 1] + "/"
            )
        except (ValueError, IndexError):
            self.method_path = ""

        self.participant = None
        if (
            "participants" in urlpath
            and not ("calls" in urlpath and "breakouts" not in urlpath)
            and self.method != "PARTICIPANTS"
        ):
            self.participant = urlpath[urlpath.index("participants") + 1]

        if "participants" not in urlpath and self.method == "DISCONNECT":
            self.method = "DISCONNECT ALL"  # Will be conference-level disconnect

        self.aux = []

        if not detail:
            self.payload = ""
        elif detail[0] == "{" and detail[-1] == "}":
            try:
                self.payload = json.loads(detail)
            except json.decoder.JSONDecodeError:
                self.payload = ast.literal_eval(detail)
            self.payload = self.payload.get("result", self.payload)
        else:
            self.payload = detail

        sdp_lines = None
        if isinstance(self.payload, dict) and isinstance(
            self.payload.get("sdp", None), str
        ):
            sdp_lines = self.payload["sdp"].split("^M")
        elif self.method == "UPDATE" and str(self.payload).startswith("v=0"):
            sdp_lines = self.payload.split("^M")

        if sdp_lines:
            client_ip = None
            m_line = ""
            for line in sdp_lines:
                if len(line) > 1 and line[1] == "=":
                    if line.startswith("m="):
                        cols = line.split()
                        if m_line:
                            self.aux.append(m_line)
                        m_line = " ".join(cols[:2])
                    elif line.startswith("c=") and not client_ip:
                        client_ip = line.strip()
                    elif line in ("a=sendonly", "a=recvonly", "a=inactive"):
                        m_line += f" [{line[2:]}]"
                    elif line == "a=content:slides":
                        m_line += " (slides)"

            if m_line:
                self.aux.append(m_line)
            if client_ip:
                self.aux.insert(0, client_ip)

        if (
            (
                self.method
                in [
                    "REQUEST_TOKEN",
                    "REQUEST_TOWNHALL_TOKEN",
                    "TEAMS_REQUEST_TOKEN",
                    "TEAMS_CONFIGURE_MEDIA",
                ]
            )
            and self.from_addr
            and isinstance(self.payload, dict)
        ):
            if "display_name" in self.payload and self.payload["display_name"]:
                self.from_addr += " ({})".format(self.payload["display_name"])
            if "participant_uuid" in self.payload:
                self.call = self.payload["participant_uuid"]
            if "media" in self.payload:
                keys = ["audio", "video", "presentation"]
                for key in keys:
                    if key in self.payload["media"]:
                        self.aux.append(
                            "{} {}:{}".format(
                                key,
                                self.payload["media"][key]["address"],
                                self.payload["media"][key]["port"],
                            )
                        )

        if (
            self.method == "CALLS"
            and isinstance(self.payload, dict)
            and "media_description" in self.payload
        ):
            if "address" in self.payload["media_description"]:
                self.aux.append(self.payload["media_description"]["address"])

            keys = ["audio", "video", "presentation"]
            for key in keys:
                if key in self.payload["media_description"]:
                    self.aux.append(
                        "{}: {}".format(
                            key, self.payload["media_description"][key]["port"]
                        )
                    )

        if self.method == "CALLS" and "call_uuid" in self.payload:
            call_map[self.payload["call_uuid"]] = self.call

    def __str__(self):
        if self.out:
            ret = f"{self.tts} {self.src} -> {self.dst} "
        else:
            ret = f"{self.tts} {self.dst} <- {self.src} "
        indent = len(ret)

        ret += self.method_path + self.method

        if isinstance(self.payload, dict):
            if self.payload.get("sdp", None):
                ret += " + SDP"

            if self.payload.get("stun", None):
                ret += " + STUN"

            if self.payload.get("turn", None):
                ret += " + TURN"

            if self.payload.get("url", None):
                ret += " (URL: {})".format(self.payload["url"])

            if "reason" in self.payload:
                ret += " (Reason: {})".format(self.payload["reason"])

            if "error" in self.payload:
                ret += " (Error: {})".format(self.payload["error"])

            if "count" in self.payload:
                ret += " (Count: {})".format(self.payload["count"])

            if "is_in_lobby" in self.payload:
                ret += " (In Lobby: {})".format(self.payload["is_in_lobby"])
            if "is_muted" in self.payload:
                ret += " (Muted: {}, Audio Restricted: {})".format(
                    self.payload["is_muted"], self.payload.get("is_audio_restricted")
                )
            if "role" in self.payload:
                ret += " (Role: {})".format(self.payload["role"])
            if self.payload.get("direct_media", False):
                ret += " (Use Direct Media)"

            if (
                self.method == "TRANSFER"
                and self.participant
                and "conference_alias" in self.payload
            ):
                ret += " (Participant-ID: {}, Target: {})".format(
                    self.participant, self.payload["conference_alias"]
                )

            if "destination" in self.payload and "protocol" in self.payload:
                ret += " (Destination: {}:{})".format(
                    self.payload["protocol"], self.payload["destination"]
                )

            if "digits" in self.payload:
                ret += " (Digits: {})".format(self.payload["digits"])

            if "candidate" in self.payload:
                if self.payload["candidate"]:
                    ice_fields = self.payload["candidate"].split()
                    ret += " ({}:{} ({}) {} mid:{})".format(
                        ice_fields[4],
                        ice_fields[5],
                        ice_fields[7],
                        ice_fields[2],
                        self.payload["mid"],
                    )
                elif self.payload["mid"]:
                    ret += " (end-of-candidates mid:{})".format(self.payload["mid"])
                else:
                    ret += " (None)"

            if "transforms" in self.payload:
                transforms = []
                for key in self.payload["transforms"]:
                    transforms.append(
                        "{}: {}".format(key.title(), self.payload["transforms"][key])
                    )

                if transforms:
                    ret += " (" + "; ".join(transforms) + ")"

            if (
                self.method == "PREFERRED_ASPECT_RATIO"
                and "aspect_ratio" in self.payload
            ):
                ret += (
                    " (Portrait)"
                    if self.payload["aspect_ratio"] < 1
                    else " (Landscape)"
                )

            if self.method == "BREAKOUTS":
                if "breakout_uuid" in self.payload:
                    ret += " (Name: {}, Breakout UUID: {})".format(
                        self.payload.get("name", "Unknown"),
                        self.payload["breakout_uuid"],
                    )
                else:
                    ret += " (Name: {})".format(self.payload["name"])
                    for src_room, participants in self.payload["participants"].items():
                        if participants:
                            for participant in participants:
                                ret += "\n{}+ {}".format(" " * indent, participant)
                        else:
                            ret += "\n{}+ {} (ALL)".format(" " * indent, src_room)

            if self.method == "BREAKOUT":
                ret += " (Breakout UUID: {})".format(
                    self.payload["breakout_uuid"],
                )
                for participant in self.payload["participants"]:
                    ret += "\n{}+ {}".format(" " * indent, participant)

            if not self.out and self.method == "CALLS" and self.participant:
                ret += f" (Participant-ID: {self.participant})"

            # Teams method
            if self.method == "ROSTER":
                roster = self.payload["roster"]
                added_users = roster.get("add", [])
                updated_users = roster.get("update", [])
                deleted_users = roster.get("delete", [])
                ret += " (Request +{} ~{} -{})".format(
                    len(added_users), len(updated_users), len(deleted_users)
                )
                for user in added_users:
                    ret += "\n" + " " * indent
                    ret += "+ {} (type: {}, presenting: {}, lobby: {}, muted: {}, spotlight: {})".format(
                        (user["display"] or user["alias"]),
                        user["type"],
                        user.get("presenting"),
                        user.get("is_in_lobby"),
                        user.get("is_muted"),
                        bool(user.get("published_states", {}).get("spotlight", False)),
                    )
                for user in updated_users:
                    ret += "\n" + " " * indent
                    ret += "~ {} (type: {}, presenting: {}, lobby: {}, muted: {}, spotlight: {})".format(
                        (user["display"] or user["alias"]),
                        user["type"],
                        user.get("presenting"),
                        user.get("is_in_lobby"),
                        user.get("is_muted"),
                        bool(user.get("published_states", {}).get("spotlight", False)),
                    )
                for user in deleted_users:
                    ret += "\n" + " " * indent
                    ret += "- {} (type: {}, presenting: {}, lobby: {}, muted: {}, spotlight: {})".format(
                        (user["display"] or user["alias"]),
                        user["type"],
                        user.get("presenting", []),
                        user.get("is_in_lobby"),
                        user.get("is_muted"),
                        bool(user.get("published_states", {}).get("spotlight", False)),
                    )
        elif self.payload != "":
            if self.method == "UPDATE" and str(self.payload).startswith("v=0"):
                ret += " + SDP"
            elif self.method == "ROSTER" and isinstance(self.payload, list):
                ret += f" (Response Total {self.external_participant_count})"
                for roster_response in self.payload:
                    ret += "\n" + " " * indent
                    ret += "+ {} (tag: {})".format(
                        self.participant_name_map.get(roster_response["id"]),
                        roster_response["tag"],
                    )
            else:
                ret += f" (Response: {self.payload})"
        elif self.participant:
            ret += f" (Participant-ID: {self.participant})"

        if self.aux and show_ports:
            ret += "\n" + (" " * indent)
            ret += "; ".join(self.aux)

        return ret

    def is_init(self):
        return (
            self.method
            in ["REQUEST_TOKEN", "REQUEST_TOWNHALL_TOKEN", "TEAMS_REQUEST_TOKEN"]
        ) and self.from_addr


class RESTEvent(Message):
    def __init__(self, event, src, dst, tts, uuid, detail, out):
        Message.__init__(self, tts)
        self.src = src
        self.dst = dst
        self.out = out
        self.call = uuid
        self.event = event.upper()
        self.aux = []

        if not detail:
            self.payload = ""
        elif detail[0] == "{" and detail[-1] == "}":
            try:
                self.payload = json.loads(detail.replace('[^\\]\\"', '"'))
            except json.decoder.JSONDecodeError:
                self.payload = ast.literal_eval(detail)
            self.payload = self.payload.get("result", self.payload)
        else:
            self.payload = detail

        sdp_lines = None
        if isinstance(self.payload, dict) and isinstance(
            self.payload.get("sdp", None), str
        ):
            sdp_lines = self.payload["sdp"].split("^M")

        if sdp_lines:
            client_ip = None
            m_line = ""
            for line in sdp_lines:
                if len(line) > 1 and line[1] == "=":
                    if line.startswith("m="):
                        cols = line.split()
                        if m_line:
                            self.aux.append(m_line)
                        m_line = " ".join(cols[:2])
                    elif line.startswith("c=") and not client_ip:
                        client_ip = line.strip()
                    elif line in ("a=sendonly", "a=recvonly", "a=inactive"):
                        m_line += f" [{line[2:]}]"
                    elif line == "a=content:slides":
                        m_line += " (slides)"

            if m_line:
                self.aux.append(m_line)
            if client_ip:
                self.aux.insert(0, client_ip)

    def __str__(self):
        if self.out:
            ret = f"{self.tts} {self.src} -> {self.dst}   "
        else:
            ret = f"{self.tts} {self.dst} <- {self.src}   "
        indent = len(ret)

        ret += "Event: " + self.event

        if isinstance(self.payload, dict):
            if self.payload.get("sdp", None):
                ret += " + SDP"
                if self.aux and show_ports:
                    ret += "\n" + (" " * indent)
                    ret += "; ".join(self.aux)
            elif self.payload.get("uuid", None) and self.payload.get(
                "display_name", None
            ):
                ret += " ({} ({}))".format(
                    self.payload.get("uuid"), self.payload.get("display_name")
                )
            elif self.payload.get("presenter_uuid", None) and self.payload.get(
                "presenter_name", None
            ):
                ret += " ({} ({}))".format(
                    self.payload.get("presenter_uuid"),
                    self.payload.get("presenter_name"),
                )
            elif self.event == "LAYOUT" and self.payload.get("view", None):
                ret += " ({})".format(self.payload.get("view"))
            elif self.event == "REFER" and self.payload.get("alias", None):
                if "breakout_name" in self.payload:
                    ret += " (-> {} ({}))".format(
                        self.payload.get("alias"), self.payload.get("breakout_name")
                    )
                else:
                    ret += " (-> {})".format(self.payload.get("alias"))
            elif self.event == "BREAKOUT_EVENT":
                ret += " ({}: {})".format(
                    self.payload.get("breakout_uuid"), self.payload.get("event").upper()
                )

        return ret

    def is_init(self):
        return False


class BFCPMessage(Message):
    def __init__(self, fields, src, dst, tts, call, out):
        Message.__init__(self, tts)
        self.fields = fields
        self.src = src
        self.dst = dst
        self.out = out
        self.call = call
        self.method = None
        self.trans_id = None
        self.req_status = None
        self.floor_req_id = None
        self.mode = None

        if "detail" in self.fields:
            msg = self.fields["detail"]
            self.method = msg[: msg.find("(")]
            self.trans_id = None
            self.req_status = None
            self.floor_req_id = None

            idx = msg.find("CommonHeader(")
            if idx < 0:
                return
            tmp = msg[idx + 13 :]
            tmp = tmp[: tmp.find(")")]
            hdr = {}
            for pair in tmp.split(", "):
                (key, value) = pair.split("=", 1)
                hdr[key] = value
            self.trans_id = hdr["trans_id"]

            idx = msg.find("request_status=")
            if idx >= 0:
                tmp = msg[idx:]
                self.req_status = tmp[tmp.find("=") + 1 : tmp.find("(")]

            idx = msg.find("floor_request_id=")
            if idx < 0:
                idx = msg.find("FloorRequestId(floor_id=")
            if idx >= 0:
                tmp = msg[idx:]
                matches = bfcp_num_field.findall(tmp)
                if matches:
                    self.floor_req_id = matches[0]

            if self.method == "HelloAck":
                self.mode = "standard" if "'FloorRequestStatusAck'" in msg else "TAA"
        else:
            self.method = self.fields["primitive"]
            self.trans_id = self.fields["transaction-id"]
            self.req_status = self.fields.get("floor-status")
            self.floor_req_id = self.fields.get("floor-request-id")
            self.mode = self.fields.get("mode")

    def __str__(self):
        if self.out:
            ret = f"{self.tts} {self.src[0]} -> {self.dst[0]}"
        else:
            ret = f"{self.tts} {self.dst[0]} <- {self.src[0]}"
        ret += f" BFCP {self.method}"
        if self.trans_id:
            ret += f" ({self.trans_id})"
        if self.floor_req_id:
            ret += f" (FloorRequestId={self.floor_req_id})"
        if self.req_status:
            ret += f" {self.req_status}"
        if self.mode:
            ret += f" {self.mode}"
        return ret


class H225Message(Message):
    def __init__(self, msg, src, dst, tts, uuid, out):
        Message.__init__(self, tts)
        # src, dst are (addr, port) tuples
        self.src = src
        self.dst = dst
        self.out = out
        self.call = uuid
        self.from_addr = ""
        self.to_addr = ""

        msg = msg[32:]
        self.method = msg[: msg.find(":")]
        self.tags = []

        state = ""
        lines = msg.split("^M")
        while lines:
            line = lines.pop(0)
            line = line.strip()

            if line.startswith("sourceAddress"):
                state = "SOURCE"
                continue
            if line.startswith("destinationAddress"):
                state = "DEST"
                continue
            if line.startswith("h245Address"):
                state = "H245"
                continue
            if line.startswith("destCallSignalAddress") and not self.to_addr:
                state = "DCSA"
                continue

            if state:
                if line.strip(":") in ["dialedDigits", "h323_ID", "url_ID", "email_ID"]:
                    line = lines.pop(0)
                    if state == "SOURCE":
                        self.from_addr = line.strip()
                    elif state == "DEST":
                        self.to_addr = line.strip()
                    state = ""
                elif line.strip(":") == "transportID":
                    if lines[1].strip().startswith("ip"):
                        line = lines.pop(0)
                        line = lines.pop(0)
                        vals = line.split()[1:]
                        if state == "SOURCE":
                            self.from_addr = ".".join([str(int(x, 16)) for x in vals])
                    state = ""
                elif state == "DCSA":
                    if line.startswith("ip"):
                        vals = line.split()[1:]
                        self.to_addr = ".".join([str(int(x, 16)) for x in vals])
                    state = ""
                elif state == "H245":
                    if line.startswith("ip"):
                        vals = line.split()[1:]
                        ipaddr = ".".join([str(int(x, 16)) for x in vals])
                        line = lines.pop(0).strip()
                        vals = line.split()
                        self.tags.append(f"ipAddress: {ipaddr}:{vals[1]}")
                    state = ""

            if line.startswith("reason"):
                self.tags.append(line.rstrip(":"))

    def __str__(self):
        if self.out:
            ret = f"{self.tts} {self.src[0]} -> {self.dst[0]}"
        else:
            ret = f"{self.tts} {self.dst[0]} <- {self.src[0]}"
        ret += f" H225 {self.method}"
        if self.tags:
            ret += " ({})".format("; ".join(self.tags))
        return ret

    def is_init(self):
        return self.method == "setup"


class H245Message(Message):
    def __init__(self, msg, src, dst, tts, uuid, out):
        Message.__init__(self, tts)
        self.src = src
        self.dst = dst
        self.out = out
        self.call = uuid

        lines = msg.split("^M")
        lines.pop(0)
        line = lines.pop(0)
        self.method = line.strip()
        self.method = self.method.rstrip(":")
        self.tags = []
        while lines:
            line = lines.pop(0)
            line = line.strip()
            if any(
                line.startswith(p)
                for p in [
                    "sequenceNumber",
                    "forwardLogicalChannelNumber",
                    "logicalChannelNumber",
                    "type",
                    "decision",
                    "mediaType",
                    "signalType",
                    "cause",
                ]
            ):
                self.tags.append(line.rstrip(":"))
            elif line.startswith("alphanumeric"):
                self.tags.append(line + " " + lines.pop(0).strip())
            elif line.startswith("forwardLogicalChannelParameters: dataType:"):
                self.tags.append(line[33:].rstrip(":"))
            elif line.startswith("mediaChannel"):
                line = lines.pop(0).strip()
                line = lines.pop(0).strip()
                if line.startswith("network"):
                    vals = line.split()[1:]
                    ipaddr = ".".join([str(int(x, 16)) for x in vals])
                    line = lines.pop(0).strip()
                    vals = line.split()
                    self.tags.append(f"ipAddress: {ipaddr}:{vals[1]}")
            elif line.startswith("subMessageIdentifier") and self.method.startswith(
                "generic"
            ):
                val = line.split()[1]
                if val == "4":
                    line = lines.pop(0)
                    line = lines.pop(0)
                    line = line.strip()
                    if line.startswith("parameterIdentifier: standard:"):
                        line = lines.pop(0)
                        line = line.strip()
                        if line == "126":
                            self.tags.append("presentationTokenResponse: acknowledge")
                        elif line == "127":
                            self.tags.append("presentationTokenResponse: reject")
                else:
                    self.tags.append(h239_types.get(val, "Unknown"))
        self.tag = "; ".join(self.tags)

    def __str__(self):
        if self.out:
            ret = f"{self.tts} {self.src[0]} -> {self.dst[0]}"
        else:
            ret = f"{self.tts} {self.dst[0]} <- {self.src[0]}"
        ret += f" H245 {self.method}"
        if self.tag:
            ret += f" ({self.tag})"
        return ret


class RTMPMessage(Message):
    def __init__(self, fields, src, dst, tts, call):
        Message.__init__(self, tts)
        self.fields = fields
        self.src = src
        self.dst = dst
        self.call = call
        self.to_addr = self.fields["url"]
        self.from_addr = self.src[0]

    def __str__(self):
        indent = len(self.tts) + 1
        ret = f"{self.tts} {self.src[0]}:{self.src[1]} -> {self.dst[0]}:{self.dst[1]}\n"
        ret += " " * indent
        ret += "{}: {} ({})".format(
            self.fields["message"], self.fields["url"], self.fields.get("src-path")
        )
        return ret

    def is_init(self):
        return True


class GMSMessage(Message):
    def __init__(self, fields, tts):
        Message.__init__(self, tts)
        self.fields = fields
        self.msg = fields.get("message")
        self.call = fields.get("call-id")
        self.request_id = fields.get("request-id")
        self.type = fields.get("type")
        self.request = None
        self.response = None
        self.to_addr = "meet.google.com"
        self.from_addr = ""
        self.payload = {}
        self.qp = {}
        self.req = ""
        if not fields.get("detail"):
            return

        # this is subtle: ensure we can continue to parse old style http and notif messages pre v34
        if self.type == "data-channel" or self.msg == "Received GMS notification":
            self._parse_type_data_channel(fields)
        else:
            self._parse_type_http(fields)

    def _parse_type_http(self, fields):
        lines = fields.get("detail").split("^M")

        if lines[0].startswith("HTTP"):
            self.req = lines[0][9:]
            return
        if fields.get("reason"):
            try:
                self.payload = json.loads(fields.get("detail", "").replace("^M", ""))
            except (ValueError, json.decoder.JSONDecodeError):
                self.payload = {"message": fields.get("detail")}
            return

        request_line = lines[0].split()
        url = urlparse(request_line[1])
        self.req = f"{request_line[0]} {url.path}"
        self.qp = parse_qs(url.query)

        # Parse HTTP headers
        headers = {}
        index = 1
        for line in lines[1:]:
            index += 1
            if not line:
                break
            key, value = line.split(": ", 1)
            headers[key] = value

        data = ""
        if index < len(lines):
            data = "\n".join(lines[index:])
        if not data:
            return

        try:
            self.payload = json.loads(data)
        except (ValueError, json.decoder.JSONDecodeError):
            self.payload = {}
        if not isinstance(self.payload, dict):
            self.payload = {}

    def _parse_type_data_channel(self, fields):
        lines = fields.get("detail").split("^M")

        error_response = False
        for i in range(len(lines)):  # pylint: disable=consider-using-enumerate
            line = lines[i]
            i += 1
            if ":" in line:
                key, val = line.split(":", 1)
                self.payload[key.strip()] = val.strip()
                continue

            if self.msg == "Received GMS notification":
                if "notification {" in line:
                    self.payload["notification"] = lines[i].strip().rstrip(" {")
                    i += 1

            elif self.msg == "Sending GMS request":
                if "media_stream_add {" in line:
                    self.req = "RPC media_stream_add"
                elif "media_stream_modify {" in line:
                    self.req = "RPC media_stream_modify"
                elif "media_stream_search {" in line:
                    self.req = "RPC media_stream_search"

            elif self.msg == "Received GMS response":
                if "status {" in line:
                    if "}" in lines[i]:
                        self.req = "RPC OK"
                    else:
                        error_response = True
                        self.req = "RPC ERROR"

        if error_response:
            try:
                rpc_errors = [
                    "OK",
                    "CANCELLED",
                    "UNKNOWN",
                    "INVALID_ARGUMENT",
                    "DEADLINE_EXCEEDED",
                    "NOT_FOUND",
                    "ALREADY_EXISTS",
                    "PERMISSION_DENIED",
                    "UNAUTHENTICATED",
                    "RESOURCE_EXHAUSTED",
                    "FAILED_PRECONDITION",
                    "ABORTED",
                    "OUT_OF_RANGE",
                    "UNIMPLEMENTED",
                    "INTERNAL",
                    "UNAVAILABLE",
                    "DATA_LOSS",
                ]
                error = rpc_errors[int(self.payload.get("code"))]
                self.req += f"({error})"
            except Exception:  # pylint: disable=broad-except  # noqa: S110
                pass

        if self.msg in ["Received GMS notification", "Received GMS response"]:
            return

        try:
            import si.signalling.gms.message.ext_hangouts as ext_hangouts_pb2
            from google.protobuf import text_format

            def _try_gms_dcrpc_decode(data):
                types = [
                    ext_hangouts_pb2.DataChannelRpcRequest,
                    ext_hangouts_pb2.DataChannelRpcResponse,
                ]
                for cls in types:
                    msg = cls()
                    try:
                        text_format.Parse(data, msg)
                        if msg.HasField("media_stream_add"):
                            return msg.media_stream_add
                        if msg.HasField("media_stream_modify"):
                            return msg.media_stream_modify
                        if msg.HasField("media_stream_search"):
                            return msg.media_stream_search
                    except text_format.ParseError:
                        continue
                return None

            msg = _try_gms_dcrpc_decode("\n".join(lines))
            if msg is None:
                return

            if isinstance(msg, ext_hangouts_pb2.MediaStreamModifyRequest):
                vsrs = []
                for stream in msg.resource:
                    if (
                        stream.direction
                        != ext_hangouts_pb2.MediaStreamDirection.Value("DOWN")
                        or not stream.request.send
                    ):
                        continue
                    vsrs.append(
                        "{}@{}p{}".format(
                            stream.offer.ssrc[0],
                            stream.request.resolution.height,
                            stream.request.resolution.frame_rate,
                        )
                    )
                self.req += " [{}]".format(", ".join(vsrs))
        except Exception:  # pylint: disable=broad-except  # noqa: S110
            pass

    def __str__(self):
        if self.response:
            ret = f"{self.tts} -> meet.google.com "
        elif self.request_id:
            ret = f"{self.tts} <- meet.google.com "
        else:
            ret = f"{self.tts} ** {self.msg}"

        if "reason" in self.fields:
            ret += self.fields["reason"]
            if self.request and self.request.req:
                ret += f" [{self.request.req}]"
            if isinstance(self.payload, dict):
                message = self.payload.get("message") or self.payload.get(
                    "error", {}
                ).get("message")
            else:
                message = self.payload
            if message:
                ret += f" ({message})"
        elif self.msg == "Received GMS notification":
            ret += " ({})".format(self.payload.get("notification"))
            if self.payload.get("notification") == "meetings_update":
                ret += " [{}: {}]".format(
                    self.payload.get("display_name"), self.payload.get("join_state")
                )
        else:
            ret += self.req

            if self.qp.get("trusted", [None])[0] == "true":
                ret += " [Trusted]"

            if self.payload.get("events"):
                ret += f" ({self.events()})"
            elif self.request and self.request.req:
                events = self.request.events()
                if events:
                    ret += f" [{self.request.req} ({events})]"
                else:
                    ret += f" [{self.request.req}]"

        return ret

    def events(self):
        if self.payload.get("events"):
            return ", ".join([e["eventType"] for e in self.payload.get("events")])
        return ""

    def is_init(self):
        return "spaces:resolve" in self.fields.get("detail", "")


class TeamsMessage(Message):
    def __init__(self, fields, tts):
        Message.__init__(self, tts)
        self.fields = fields
        self.call = fields["call-id"]
        url = urlparse(fields["request"])
        self.dst = url.hostname
        self.method = url.path.split("/")[-1].upper()
        if self.method == "SELF_MUTE_STATUS":
            self.method = "TEAMS_SELF_MUTE_STATUS"
        if self.method == "MUTE":
            self.method = "MUTE_TEAMS_PARTICIPANT"
        self.payload = {}
        if "content" in fields:
            try:
                self.payload = json.loads(fields["content"])
            except (ValueError, json.decoder.JSONDecodeError):
                self.payload = {}
        self.out = fields["message"] == "Sending Teams API request"
        self.from_addr = ""
        self.to_addr = ""
        if "remote_alias" in self.payload:
            self.from_addr = "{} <{}>".format(
                self.payload.get("remote_display_name", ""),
                self.payload.get("remote_alias", ""),
            )
            self.to_addr = "{} <{}>".format(
                self.payload.get("conference_alias", ""),
                self.payload.get("local_alias", ""),
            )

    def __str__(self):
        if self.out:
            ret = f"{self.tts} -> {self.dst} "
        else:
            ret = f"{self.tts} <- {self.dst} "
        indent = len(ret)
        ret += self.method

        if "status" in self.fields:
            ret += " {}".format(self.fields["status"])
        elif "error" in self.fields:
            ret += " (Error: {})".format(self.fields["error"])
        elif self.method == "EVENTS" and "events" in self.payload:
            events = []
            for event in self.payload["events"]:
                if event[0].upper() == "DISCONNECT" and "reason" in event[2]:
                    events.append(
                        "{} (Reason: {})".format(event[0].upper(), event[2]["reason"])
                    )
                elif (
                    event[0].upper().startswith("PARTICIPANT")
                    and event[2]
                    and "display_name" in event[2]
                ):
                    events.append(
                        "{} ({})".format(event[0].upper(), event[2]["display_name"])
                    )
                else:
                    events.append(event[0].upper())
            ret += " ({})".format(", ".join(events))
        elif self.method == "TEAMS_SELF_MUTE_STATUS" and "new_state" in self.payload:
            ret += " (Is Muted: {})".format(self.payload["new_state"])
        elif (
            self.method == "MUTE_TEAMS_PARTICIPANT"
            and "teams_participant_uuid" in self.payload
        ):
            ret += " (Teams Participant UUID: {})".format(
                self.payload["teams_participant_uuid"]
            )

        if "succeeded" in self.payload:
            ret += " (Succeeded: {}".format(self.payload["succeeded"])
            if isinstance(self.payload.get("result"), dict):
                if "contact" in self.payload["result"]:
                    ret += ", Contact: {}".format(self.payload["result"]["contact"])
            if "version" in self.payload:
                ret += ", Version: {}".format(self.payload["version"])
            ret += ")"

        if "media" in self.payload:
            keys = ["audio", "video", "presentation"]
            vals = []
            if self.payload["media"]:
                for key in keys:
                    if key in self.payload["media"]:
                        vals.append(
                            "{} {}:{}".format(
                                key,
                                self.payload["media"][key]["address"],
                                self.payload["media"][key]["port"],
                            )
                        )
                if vals:
                    ret += "\n" + " " * indent + "; ".join(vals)
            else:
                ret += "\n" + " " * indent + "[No media]"

        if self.payload.get("treat_as_trusted"):
            ret += " [Trusted]"

        return ret

    def is_init(self):
        return self.method == "INCOMING"


class TeamsCustomMessage(Message):
    def __init__(self, fields, tts):
        Message.__init__(self, tts)
        self.msg = fields["message"]
        self.fields = fields
        self.call = fields.get("call-id")

    def __str__(self):
        ret = self.tts + " "
        ret += f"** {self.msg}"
        fs = []
        for f in self.fields:
            if f not in ["message", "call-id", "level", "name"]:
                fs.append(f"{f}: {self.fields[f]}")
        ret += " ({})".format(", ".join(fs))
        return ret


class LogMessage(Message):
    def __init__(self, fields, tts):
        Message.__init__(self, tts)
        self.msg = fields["message"]
        self.fields = fields
        self.call = fields.get("call-id")

    def __str__(self):
        ret = self.tts + " "
        indent = len(ret)
        ret += f"** {self.msg}"
        presenter = self.fields.get("presenter", self.fields.get("last-presenter"))
        if presenter:
            ret += f", presenter = {presenter}"
        #        conversation_id = self.fields.get("conversation-id")
        #        if conversation_id:
        #            ret += ", conversation-id = %s" % conversation_id
        detail = self.fields.get("detail")
        if "dst-address" in self.fields:
            ret += " towards {}:{} [{}]".format(
                self.fields.get("dst-address"),
                self.fields.get("dst-port"),
                self.fields.get("protocol"),
            )

        if "state" in self.fields:
            ret += ", state = {}".format(self.fields.get("state"))

        if "breakout-room" in self.fields:
            ret += "\n{}   Conference: {}".format(
                " " * indent, self.fields.get("breakout-room")
            )

        if "requester" in self.fields:
            for field in set(self.fields.keys()) & {
                "to-conference",
                "text",
                "digits",
                "role",
                "breakout-name",
            }:
                ret += f' {field.title()}="{self.fields[field]}"'
            ret += "\n{}   Requested by {}".format(
                " " * indent, self.fields["requester"]
            )

        if detail:
            if detail.endswith("^M]"):
                detail = detail[:-3] + "]"

            if "^M" in detail:
                for line in detail.split("^M"):
                    ret += "\n{}{}".format(" " * indent, line)
            elif detail.startswith("["):
                ret += "\n{}{}".format(" " * indent, detail)
            else:
                ret += f" ({detail})"
        return ret


class DTMFMessage(Message):
    def __init__(self, fields, tts):
        Message.__init__(self, tts)
        self.msg = fields["message"]
        self.fields = fields
        self.call = fields.get("call-id")

    def __str__(self):
        ret = self.tts + " "
        if "mechanism" in self.fields:
            ret += "** {} ({} [{}])".format(
                self.msg, self.fields.get("digit"), self.fields.get("mechanism")
            )
        else:
            ret += "** {} ({})".format(self.msg, self.fields.get("digit"))
        return ret


class ICEMessage(Message):
    def __init__(self, msg, fields, tts):
        Message.__init__(self, tts)
        self.msg = msg
        self.fields = fields
        self.call = fields.get("call-id")

    def __str__(self):
        ret = self.tts + " "
        indent = len(ret)
        ret += f"** {self.msg}: "
        ret += "Stream {} ({}), Component {}".format(
            self.fields.get("stream-id"),
            self.fields.get("media-type"),
            self.fields.get("component-id"),
        )
        if "new-selected-pair" in self.msg:
            ret += "\n" + (" " * indent)
            ret += "{}:{} ({}) {} <-> {}:{} ({}) {}".format(
                self.fields.get("local-candidate-address"),
                self.fields.get("local-candidate-port"),
                self.fields.get("local-candidate-type"),
                self.fields.get("local-candidate-transport"),
                self.fields.get("remote-candidate-address"),
                self.fields.get("remote-candidate-port"),
                self.fields.get("remote-candidate-type"),
                self.fields.get("remote-candidate-transport"),
            )
        return ret

    def __eq__(self, other):
        return (
            self.fields.get("local-candidate-address")
            == other.fields.get("local-candidate-address")
            and self.fields.get("local-candidate-port")
            == other.fields.get("local-candidate-port")
            and self.fields.get("remote-candidate-address")
            == other.fields.get("remote-candidate-address")
            and self.fields.get("remote-candidate-port")
            == other.fields.get("remote-candidate-port")
        )

    def getMediaType(self):
        return self.fields.get("media-type")

    def getKey(self):
        return "{}:{}".format(
            self.fields.get("stream-id"), self.fields.get("component-id")
        )


class MediaMessage(Message):
    def __init__(self, msg, fields, tts):
        Message.__init__(self, tts)
        self.msg = msg
        self.fields = fields
        self.call = fields.get("call-id")

    def __str__(self):
        ret = self.tts + " "
        ret += f"** {self.msg}: "
        if "stream-id" in self.fields:
            ret += "Stream {} ({})".format(
                self.fields.get("stream-id"), self.fields.get("media-type")
            )
        if "mode" in self.fields:
            ret += ", {}".format(self.fields.get("mode"))
        if "latched-remote-address" in self.fields:
            ret += ", Component {}, {}:{} -> {}:{}".format(
                self.fields.get("component-id"),
                self.fields.get("latched-remote-address"),
                self.fields.get("latched-remote-port"),
                self.fields.get("signalled-remote-address"),
                self.fields.get("signalled-remote-port"),
            )
        if self.fields["message"].startswith("Stable call quality changed"):
            ret += "Was {} -> Now {}".format(
                self.fields.get("was"), self.fields.get("now")
            )
        return ret


class LostIncomingVideoMessage(Message):
    def __init__(self, fields, tts):
        Message.__init__(self, tts)
        self.fields = fields
        self.call = fields.get("call-id")
        self.stream_id = int(self.fields["detail"].split(" ")[1])
        self.stream_id_participant_name_map = None

    def __str__(self):
        ret = self.tts + " "
        ret += "** {}:".format(self.fields["message"])
        ret += " " + self.fields["detail"]
        participant_name = self.stream_id_participant_name_map.get(self.stream_id)
        if participant_name:
            ret += " (" + participant_name + ")"
        return ret


class ParticipantMediaStreamWindow(Message):
    PACKET_LOSS_FORMAT_STRING = (
        "{:>20} {:>12} {:>12} {:>12} {:>6} {:>12} {:>12} {:>12} {:>6}     {:>9} {:>6}"
    )
    RECENT_QUALITY_FORMAT_STRING = "{:>12} {:>12} {:>12} {:>9} {:>8}"

    def __init__(self, host, fields, tts, participant_to_call):
        Message.__init__(self, tts)
        content = fields["content"]
        if content.startswith("b'"):
            content = content[2:-1]
        self.host = host
        self.call = None
        self.packet_loss_reports = {
            "audio": defaultdict(list),
            "video": defaultdict(list),
            "presentation": defaultdict(list),
        }
        self.recent_quality_reports = []

        try:
            content = json.loads(content)
        except (ValueError, json.decoder.JSONDecodeError):
            pass
        else:
            self.call = participant_to_call.get(content["uuid"], content["uuid"])

            # Collate historical packet stats by stream type
            for packet_loss_report in content["packet_loss_history"]:
                self.packet_loss_reports[packet_loss_report["type"]][
                    packet_loss_report["id"]
                ].append(packet_loss_report)

            # Sort state by time
            for stream_type_packet_loss_report in self.packet_loss_reports.values():
                for (
                    stream_id_packet_loss_report
                ) in stream_type_packet_loss_report.values():
                    stream_id_packet_loss_report.sort(key=itemgetter("time"))

            # Collate recent call quaity stats by stream type
            self.recent_quality_reports = sorted(
                content["recent_quality"], key=itemgetter("time")
            )

    def __str__(self):
        if self.call is None:
            return ""
        ret = self.tts + " "
        ret += "** "
        indent = len(ret)
        ret += "Packet loss report " + self.host
        reports = []

        for stream_type in ["audio", "video", "presentation"]:
            for stream_id in sorted(
                self.packet_loss_reports[stream_type].keys(), key=str
            ):
                stream_name = f"{stream_type}-{stream_id}"

                last_packet_loss_report = {}
                for packet_loss_report in self.packet_loss_reports[stream_type][
                    stream_id
                ]:
                    if all(
                        [
                            packet_loss_report[stat] == 0
                            for stat in [
                                "rx_packets_received",
                                "rx_packets_lost",
                                "tx_packets_sent",
                                "tx_packets_lost",
                            ]
                        ]
                    ):
                        continue

                    if last_packet_loss_report:
                        reports.append(
                            self.PACKET_LOSS_FORMAT_STRING.format(
                                stream_name,
                                packet_loss_report["rx_packets_received"],
                                packet_loss_report["rx_packets_received"]
                                - last_packet_loss_report["rx_packets_received"],
                                packet_loss_report["rx_packets_lost"],
                                packet_loss_report["rx_packets_lost"]
                                - last_packet_loss_report["rx_packets_lost"],
                                packet_loss_report["tx_packets_sent"],
                                packet_loss_report["tx_packets_sent"]
                                - last_packet_loss_report["tx_packets_sent"],
                                packet_loss_report["tx_packets_lost"],
                                packet_loss_report["tx_packets_lost"]
                                - last_packet_loss_report["tx_packets_lost"],
                                strftime(
                                    "%H:%M:%S", gmtime(packet_loss_report["time"])
                                ),
                                "{:03.2f}s".format(
                                    packet_loss_report["time"]
                                    - last_packet_loss_report["time"]
                                ),
                            )
                        )
                    else:
                        reports.append(
                            self.PACKET_LOSS_FORMAT_STRING.format(
                                stream_name,
                                packet_loss_report["rx_packets_received"],
                                "",
                                packet_loss_report["rx_packets_lost"],
                                "",
                                packet_loss_report["tx_packets_sent"],
                                "",
                                packet_loss_report["tx_packets_lost"],
                                "",
                                strftime(
                                    "%H:%M:%S", gmtime(packet_loss_report["time"])
                                ),
                                "",
                            )
                        )

                    stream_name = ""
                    last_packet_loss_report = packet_loss_report

        if reports:
            ret += "\n" + " " * indent
            ret += self.PACKET_LOSS_FORMAT_STRING.format(
                "Stream",
                "Rx packets",
                "+",
                "Rx lost",
                "+",
                "Tx packets",
                "+",
                "Tx lost",
                "+",
                "Timestamp",
                "+",
            )
            ret += "\n" + " " * indent
            ret += ("\n" + " " * indent).join(reports)

        ret += "\n" + self.tts + " ** Recent quality report " + self.host
        ret += "\n" + " " * indent
        ret += self.RECENT_QUALITY_FORMAT_STRING.format(
            "Audio", "Video", "Presentation", "Timestamp", "+"
        )
        last_recent_quality_report = {}
        for recent_quality_report in self.recent_quality_reports:
            ret += "\n" + " " * indent
            ret += self.RECENT_QUALITY_FORMAT_STRING.format(
                stable_call_quality_to_text(recent_quality_report, "audio"),
                stable_call_quality_to_text(recent_quality_report, "video"),
                stable_call_quality_to_text(recent_quality_report, "presentation"),
                strftime("%H:%M:%S", gmtime(recent_quality_report["time"])),
                "{:03.2f}s".format(
                    recent_quality_report["time"] - last_recent_quality_report["time"]
                )
                if last_recent_quality_report
                else "",
            )
            last_recent_quality_report = recent_quality_report
        return ret


class PSOMMessage(Message):
    def __init__(self, fields, tts):
        Message.__init__(self, tts)
        self.msg = fields["message"]
        self.fields = fields
        self.call = fields.get("call-id")

    def __str__(self):
        ret = self.tts + " "
        indent = len(ret)
        ret += "** " + self.msg
        if "local-address" in self.fields:
            ret += "\n" + (" " * indent)
            ret += "   {}:{} -> {}:{}".format(
                self.fields.get("local-address"),
                self.fields.get("local-port"),
                self.fields.get("remote-address"),
                self.fields.get("remote-port"),
            )
        elif "target-fqdn" in self.fields:
            ret += ": {} {}s:{}]".format(
                self.fields.get("target-fqdn"),
                self.fields.get("remote-address"),
                self.fields.get("remote-port"),
            )

        elif "remote-address" in self.fields:
            ret += " [{}:{}]".format(
                self.fields.get("remote-address"), self.fields.get("remote-port")
            )

        if "error" in self.fields:
            ret += "\n{}   ({})".format(" " * indent, self.fields.get("error"))

        return ret


class VSRMessage(Message):
    # Frame rate bit mask definitions
    FRAME_RATE_MASK_7_5 = 0x01
    FRAME_RATE_MASK_12_5 = 0x02
    FRAME_RATE_MASK_15 = 0x4
    FRAME_RATE_MASK_25 = 0x8
    FRAME_RATE_MASK_30 = 0x10
    FRAME_RATE_MASK_50 = 0x20
    FRAME_RATE_MASK_60 = 0x40
    FRAME_RATE_MASK_1_875 = 0x80
    FRAME_RATE_MASK_3_75 = 0x100

    FRAME_RATE_TO_TEXT = {
        FRAME_RATE_MASK_1_875: "1.875",
        FRAME_RATE_MASK_3_75: "3.75",
        FRAME_RATE_MASK_7_5: "7.5",
        FRAME_RATE_MASK_12_5: "12.5",
        FRAME_RATE_MASK_15: "15",
        FRAME_RATE_MASK_25: "25",
        FRAME_RATE_MASK_30: "30",
        FRAME_RATE_MASK_50: "50",
        FRAME_RATE_MASK_60: "60",
    }

    def __init__(self, msg, fields, tts):
        Message.__init__(self, tts)
        self.msg = msg
        self.fields = fields
        self.call = fields.get("call-id")
        self.sender_ssrc = fields.get("sender-ssrc")
        self.msi = fields.get("msi")
        self.modes = ast.literal_eval(fields.get("modes"))
        self.participant_name_map = None
        self.tag_participant_map = None
        self.ssrc_stream_id_map = None
        self.stream_id_participant_name_map = {}

    @staticmethod
    def framerates(framerate_mask):
        """Returns all framerates in VSR."""
        return ",".join(
            [
                value
                for mask, value in VSRMessage.FRAME_RATE_TO_TEXT.items()
                if (framerate_mask & mask) != 0
            ]
        )

    def mode_summary(self):
        ret = "["

        summaries = []
        for mode in self.modes:
            summaries.append(
                "pt:{} {}x{}@{}fps {}bps".format(
                    mode["pt"],
                    mode["max_width"],
                    mode["max_height"],
                    self.framerates(mode["framerate_mask"]),
                    mode["min_bitrate"],
                )
            )

        ret += ", ".join(summaries)
        ret += "]"

        return ret

    def __str__(self):
        (stream_id, stream_name) = self.ssrc_stream_id_map.get(
            int(self.sender_ssrc), (0, "")
        )
        remote_ssrc = " ".join(
            [
                str(_ssrc)
                for _ssrc, (_stream_id, _stream_name) in self.ssrc_stream_id_map.items()
                if stream_name == _stream_name and _ssrc != int(self.sender_ssrc)
            ]
        )
        if stream_name:
            stream_name += " "
        stream_name += f"(sender ssrc: {self.sender_ssrc}, remote ssrc: {remote_ssrc})"
        participant_id = self.tag_participant_map.get(self.msi)
        participant_name = self.participant_name_map.get(participant_id, "")
        if participant_name:
            if self.msg == "Sent VSR":
                self.stream_id_participant_name_map[stream_id] = participant_name
            participant_name += " "
        participant_name += f"(msi: {self.msi})"

        ret = self.tts + " "
        ret += f"** {self.msg}: {stream_name} {participant_name} {self.mode_summary()}"
        return ret

    def __eq__(self, other):
        return (
            self.sender_ssrc == other.sender_ssrc
            and self.msi == other.msi
            and self.mode_summary() == other.mode_summary()
        )

    def __ne__(self, other):
        return not self.__eq__(other)


class DNSMessage(Message):
    def __init__(self, fields, tts):
        Message.__init__(self, tts)
        self.fields = fields
        self.call = fields.get("call-id")

    def path(self):
        path = []
        if self.fields.get("path"):
            for element in self.fields["path"].split("=>"):
                groups = path_element.match(element)
                path.append((groups.group(1), groups.group(2)))
        return path

    def target(self):
        if self.fields.get("type", "") == "SRV":
            return self.fields["service"]
        if self.fields.get("type", "") == "NAPTR":
            return self.fields["domain"]
        if self.fields.get("path"):
            return self.path()[0][1]
        return self.fields["target"]


class DNSResponse(DNSMessage):
    def __init__(self, fields, tts):
        DNSMessage.__init__(self, fields, tts)
        self.success = "success" in self.fields["message"]
        self.result = self.fields.get("result", "")

    def __str__(self):
        ret = self.tts + " ** "
        ind = len(ret)
        ret += "DNS Query: {} ({})\n".format(self.target(), self.fields.get("type"))
        if self.success:
            ret += (ind * " ") + "=> "
            if "=>" in self.fields.get("path", ""):
                for item in self.path():
                    ret += f"{item[1]} ({item[0]}) => "
            ret += self.result
        else:
            ret += ind * " "
            ret += self.fields["message"]
            if "details" in self.fields:
                ret += " ({})".format(self.fields["details"])
        return ret

    def __eq__(self, other):
        return str(self) == str(other) and self.target() == other.target()

    def __ne__(self, other):
        return not self.__eq__(other)


class AdminMessage(Message):
    def __init__(self, fields, tts, participant_to_call):
        Message.__init__(self, tts)
        self.fields = fields
        self.call = fields.get("call-id")
        participant_to_call[fields.get("participant-id", self.call)] = self.call


class TCPMessage(Message):
    def __init__(self, msg, local, remote, tts, detail, uuid=None):
        Message.__init__(self, tts)
        self.msg = msg
        self.local = local
        self.remote = remote
        self.detail = detail
        self.call = uuid

    @property
    def timestamp(self):
        return datetime.strptime(self.tts, "%Y-%m-%d %H:%M:%S,%f")

    def __str__(self):
        ret = self.tts + " ** " + self.msg + ": "
        ind = len(ret)
        if self.local[0]:
            ret += "{}:{} <-> {}:{}".format(
                self.local[0], self.local[1], self.remote[0], self.remote[1]
            )
        else:
            ret += f"-> {self.remote[0]}:{self.remote[1]}"
        if self.detail:
            ret += "\n{}({})".format(ind * " ", self.detail)
        return ret


class ExternalSpeakerMessage(Message):
    def __init__(self, msg, fields, tts):
        Message.__init__(self, tts)
        self.msg = msg
        self.call = fields["call-id"]
        self.last_seen_msi = fields.get("last-seen-msi")
        self.msi = fields.get("msi")
        self.participant_name_map = None
        self.tag_participant_map = None
        self.ssrc_stream_id_map = None

    def __str__(self):
        participant_names = []
        for msi in [self.msi, self.last_seen_msi]:
            if msi is not None:
                participant_id = self.tag_participant_map.get(msi)
                participant_name = self.participant_name_map.get(participant_id, "")
                if participant_name:
                    participant_name += " "
                    participant_name += f"({msi})"
            else:
                participant_name = "None"
            participant_names.append(participant_name)

        return "{} ** {}: (msi: {}, last-seen: {})".format(
            self.tts, self.msg, participant_names[0], participant_names[1]
        )


def tokenize(stuff):
    fields = {}
    while '="' in stuff:
        equ = stuff.find('="')
        key = stuff[:equ]
        stuff = stuff[equ + 2 :]
        if stuff.startswith("^M"):
            stuff = stuff[2:]
            quot = -2
        else:
            loc = quot_end.search(stuff)
            quot = loc.start() if loc else -1
        value = stuff[:quot]
        fields[key.lower()] = value.replace('\\"', '"')
        stuff = stuff[quot + 2 :]

    return fields


def parse_args(args=None):
    parser = argparse.ArgumentParser(
        description="Parses support logs to display digest of calls"
    )
    parser.add_argument(
        "log_files", metavar="FILE", nargs="*", help="support log file to parse"
    )
    parser.add_argument(
        "--no-bfcp", action="store_true", help="don't show BFCP messages"
    )
    parser.add_argument(
        "--no-spam", action="store_true", help="don't show sipvicious (sipcli) spam"
    )
    parser.add_argument(
        "--no-ports", action="store_true", help="don't show SIP media ports"
    )
    parser.add_argument("--no-ice", action="store_true", help="don't show ICE logging")
    parser.add_argument(
        "--no-media", action="store_true", help="don't show media logging"
    )
    parser.add_argument("--no-vsr", action="store_true", help="don't show VSR logging")
    parser.add_argument(
        "--no-audio-msi", action="store_true", help="don't show audio MSI logging"
    )
    parser.add_argument(
        "--filter",
        metavar="STRING",
        type=str.upper,
        help="from/to address to filter on",
    )
    parser.add_argument(
        "--protocol", metavar="STRING", type=str.upper, help="protocol(s) to filter on"
    )
    return parser.parse_args(args=args)


def coalesce_fragments(fragments):
    """
    Reassemble SIPMessageFragment into SIPMessage objects. Return back a list of tuples
    of (SIPMessage, host).
    """
    msgs = []
    # Re-assemble fragments
    for fragment_list in fragments:
        fragment_list.sort(key=attrgetter("fragment_number"))
        detail = "".join([fragment.detail for fragment in fragment_list])
        first_fragment = fragment_list[0]
        msg = SIPMessage(
            detail,
            first_fragment.src,
            first_fragment.dst,
            first_fragment.proto,
            first_fragment.tts,
            first_fragment.out,
        )

        msg.missing_fragments = first_fragment.fragment_total - len(fragment_list)
        msgs.append((msg, first_fragment.host))
    return msgs


def add_msg_to_calls(msg, calls, host):
    if msg.call in calls:
        call = calls[msg.call]
    else:
        call = calls[msg.call] = Call(msg.call)

    if (
        isinstance(msg, LogMessage)
        and msg.fields.get("name", "").startswith("support.participant")
    ) or isinstance(msg, (ICEMessage, MediaMessage, AdminMessage)):
        call.media_host = host
    elif isinstance(
        msg, (SIPMessage, H225Message, H245Message, RESTMessage, GMSMessage)
    ):
        call.signaling_host = host

    call.add_msg(msg)


def add_msgs_to_calls(msgs, calls):
    for msg, host in msgs:
        add_msg_to_calls(msg, calls, host)


def main():
    args = parse_args()
    # pylint: disable-msg=global-statement
    global show_ports, no_bfcp, no_ice, no_media, no_vsr, no_audio_msi
    show_ports = not args.no_ports
    no_bfcp = args.no_bfcp
    no_ice = args.no_ice
    no_media = args.no_media
    no_vsr = args.no_vsr
    no_audio_msi = args.no_audio_msi
    # pylint: enable-msg=global-statement
    filter_name = args.filter
    if args.protocol:
        protocol_filter = args.protocol.split(",")
    else:
        protocol_filter = []
    no_spam = args.no_spam

    try:
        log_files = sorted(args.log_files, key=os.path.getmtime)
    except OSError as err:
        print(err)
        sys.exit(2)

    fi = fileinput.input(log_files, openhook=fileinput.hook_encoded("utf-8"))
    fo = sys.stdout

    summarise(fi, fo, filter_name, protocol_filter, no_spam)


def summarise(fi, fo, filter_name=None, protocol_filter=None, no_spam=False):
    calls = {}  # maps call-id -> Call
    tcpmsgs = {}
    fragments = {}
    participant_to_call = {}

    for line in fi:
        if (
            all(
                p not in line
                for p in [
                    "Sending",
                    "Received",
                    "support.participant",
                    "support.participantpresentationmodule",
                    "support.ice",
                    "support.media",
                    "support.dns",
                    "support.sip",
                    "support.ms_data_conf.ms_data_conf",
                    "administrator.conference",
                    "SIP Transport Failure",
                    "support.rtmp",
                    "support.gms",
                    "support.teams",
                    "support.dtmf",
                    "dtmflatcher",
                    "dtmf_latcher",
                ]
            )
            and not (
                "support.h323.h245" in line
                and "TCP Connection" in line
                and "Uuid" in line
            )
            and not (
                "support.h323.q931" in line
                and "TCP Connection" in line
                and "Uuid" in line
            )
        ):
            continue
        # ignore syslog timestamp as we can't rely on it
        line = line[30:]
        # line = 'us-mns-wrk1 2014-08-01 13:14:02,030 Level="INFO" ...'
        preamble = line.split(None, 3)
        host = preamble[0]
        tts = " ".join(preamble[1:3])
        fields = tokenize(preamble[3])
        if "message" not in fields or (
            "name" not in fields
            and "Got DTMF digit" not in line
            and "Sending DTMF digit" not in line
            and "participant_media_stream_window" not in line
        ):
            continue

        fragment_id = fields.get("fragment-id")
        if fields.get("name") == "support.sip" and fragment_id is not None:
            out = fields["message"].startswith("Sending SIP")
            msg = SIPMessageFragment(
                host,
                fields["detail"],
                (fields["src-address"], fields["src-port"]),
                (fields["dst-address"], fields["dst-port"]),
                fields["transport"],
                tts,
                fragment_id,
                fields["fragment-number"],
                fields["fragment-total"],
                out,
            )
            if fragment_id not in fragments:
                fragments[fragment_id] = [msg]
            else:
                fragments[fragment_id].append(msg)
            continue
        if "DTMF digit" in fields["message"]:
            msg = DTMFMessage(fields, tts)
        elif "participant_media_stream_window" in line:
            if "management_queue" not in line:
                continue
            msg = ParticipantMediaStreamWindow(host, fields, tts, participant_to_call)
        elif fields["name"] == "support.participant":
            if fields["message"] == "Lost incoming video":
                msg = LostIncomingVideoMessage(fields, tts)
            else:
                msg = LogMessage(fields, tts)
        elif fields["name"] == "support.participantpresentationmodule":
            msg = LogMessage(fields, tts)
        elif (
            fields["name"] == "support.media"
            and fields["message"] == "Media Stream destroyed"
        ):
            msg = LogMessage(fields, tts)
        elif fields["message"].startswith("ICE new-selected-pair") or fields[
            "message"
        ].startswith("ICE failed"):
            msg = ICEMessage(fields["message"], fields, tts)
        elif fields["message"].startswith("New mode activated"):
            msg = MediaMessage(fields["message"], fields, tts)
        elif "latching" in fields["message"]:
            msg = MediaMessage(fields["message"], fields, tts)
        elif fields["message"].startswith("Stable call quality changed"):
            msg = MediaMessage(fields["message"], fields, tts)
        elif "VSR" in fields["message"]:
            msg = VSRMessage(fields["message"], fields, tts)
        elif "Receiving audio MSI" in fields["message"]:
            msg = ExternalSpeakerMessage(fields["message"], fields, tts)
        elif (
            fields["message"] == "Participant has joined."
            or fields["message"] == "Participant has disconnected."
        ) and fields.get("protocol", "Unknown") != "BACKPLANE":
            msg = AdminMessage(fields, tts, participant_to_call)
        elif fields["name"] == "administrator.conference" and fields.get("call-id"):
            msg = LogMessage(fields, tts)
        elif (
            fields["name"] == "administrator.conference"
            and fields.get("participant-id")
            and fields["participant-id"] in participant_to_call
        ):
            fields["call-id"] = participant_to_call[fields["participant-id"]]
            msg = LogMessage(fields, tts)
        elif "PIN" in fields["message"]:
            msg = LogMessage(fields, tts)
        elif "record lookup" in fields["message"].lower() and fields["type"] != "AAAA":
            msg = DNSResponse(fields, tts)
        elif fields["message"].startswith("SIP Transport Failure"):
            msg = LogMessage(fields, tts)
        elif fields["message"].startswith("Summarised sending SIP"):
            try:
                msg = SIPSummaryMessage(
                    fields,
                    (fields["src-address"], fields["src-port"]),
                    (fields["dst-address"], fields["dst-port"]),
                    fields["transport"],
                    tts,
                    True,
                )
            except KeyError:
                continue
        elif (
            fields["message"].startswith("Summarised received SIP")
            and not fields["method"] == "REGISTER"
        ):
            try:
                msg = SIPSummaryMessage(
                    fields,
                    (fields["src-address"], fields["src-port"]),
                    (fields["dst-address"], fields["dst-port"]),
                    fields["transport"],
                    tts,
                    False,
                )
            except KeyError:
                continue
        elif fields["message"].startswith("Sending SIP"):
            msg = SIPMessage(
                fields["detail"],
                (fields["src-address"], fields["src-port"]),
                (fields["dst-address"], fields["dst-port"]),
                fields["transport"],
                tts,
                True,
            )
        elif fields["message"].startswith("Received SIP"):
            msg = SIPMessage(
                fields["detail"],
                (fields["src-address"], fields["src-port"]),
                (fields["dst-address"], fields["dst-port"]),
                fields["transport"],
                tts,
                False,
            )
        elif fields["message"] == "Sending H.225 message":
            msg = H225Message(
                fields["detail"],
                (fields.get("src-address", ""), fields.get("src-port", "")),
                (fields["dst-address"], fields["dst-port"]),
                tts,
                fields["uuid"],
                True,
            )
        elif fields["message"] == "Received H.225 message":
            msg = H225Message(
                fields["detail"],
                (fields["src-address"], fields["src-port"]),
                (fields.get("dst-address", ""), fields.get("dst-port", "")),
                tts,
                fields["uuid"],
                False,
            )
        elif fields["message"] == "Sending H.245 message":
            msg = H245Message(
                fields["detail"],
                (fields.get("src-address", ""), fields.get("src-port", "")),
                (fields["dst-address"], fields["dst-port"]),
                tts,
                fields["uuid"],
                True,
            )
        elif fields["message"] == "Received H.245 message":
            msg = H245Message(
                fields["detail"],
                (fields["src-address"], fields["src-port"]),
                (fields.get("dst-address", ""), fields.get("dst-port", "")),
                tts,
                fields["uuid"],
                False,
            )
        elif fields["message"].startswith("Sending WebRTC"):
            msg = WebRTCMessage(
                fields["detail"],
                (fields["src-address"], fields["src-port"]),
                fields.get("fwd-address", fields["dst-address"]),
                tts,
                fields["conferencealias"],
                fields["uuid"],
                True,
            )
        elif fields["message"].startswith("Received WebRTC"):
            msg = WebRTCMessage(
                fields["detail"],
                fields.get("fwd-address", fields["src-address"]),
                (fields["dst-address"], fields["dst-port"]),
                tts,
                fields["conferencealias"],
                fields["uuid"],
                False,
            )
        elif (
            fields["message"] == "Received REST API request"
            and "v2/conferences" in fields["request"]
        ):
            msg = RESTMessage(
                fields["request"],
                ("{} [{}]".format(fields["src-address"], fields["fwd-address"]))
                if "fwd-address" in fields
                else fields["src-address"],
                fields["dst-address"],
                tts,
                fields.get("uuid", None),
                fields.get("detail", None),
                False,
            )
        elif (
            fields["message"] == "Sending REST API response"
            and "v2/conferences" in fields["request"]
        ):
            msg = RESTMessage(
                fields["request"],
                fields["src-address"],
                ("{} [{}]".format(fields["dst-address"], fields["fwd-address"]))
                if "fwd-address" in fields
                else fields["dst-address"],
                tts,
                fields.get("uuid", None),
                fields.get("detail", None),
                True,
            )
        elif fields["message"] == "Sending REST API event":
            msg = RESTEvent(
                fields["event"],
                fields["src-address"],
                ("{} [{}]".format(fields["dst-address"], fields["fwd-address"]))
                if "fwd-address" in fields
                else fields["dst-address"],
                tts,
                fields.get("uuid", None),
                fields.get("detail", None),
                True,
            )
        elif fields["message"] == "Sending BFCP message":
            try:
                msg = BFCPMessage(
                    fields,
                    (fields["src-address"], fields["src-port"]),
                    (fields["dst-address"], fields["dst-port"]),
                    tts,
                    fields["call-id"],
                    True,
                )
            except KeyError:
                continue
        elif fields["message"] == "Received BFCP message":
            try:
                msg = BFCPMessage(
                    fields,
                    (fields["src-address"], fields["src-port"]),
                    (fields["dst-address"], fields["dst-port"]),
                    tts,
                    fields["call-id"],
                    False,
                )
            except KeyError:
                continue
        elif fields["name"] == "support.rtmp":
            msg = RTMPMessage(
                fields,
                (fields["src-address"], fields["src-port"]),
                (fields["dst-address"], fields["dst-port"]),
                tts,
                fields["call-id"],
            )
        elif fields["name"] == "support.gms":
            # Process only first fragment (should contain all the important information, fixes #16980
            if "fragment-number" not in fields or fields.get("fragment-number") == "1":
                msg = GMSMessage(fields, tts)
            else:
                continue
        elif fields["name"] == "support.ms_data_conf.ms_data_conf" and fields.get(
            "call-id"
        ):
            msg = PSOMMessage(fields, tts)
        elif (
            fields["name"] == "support.teams"
            and fields.get("call-id", "None") != "None"
        ):
            if "request" in fields:
                msg = TeamsMessage(fields, tts)
            else:
                msg = TeamsCustomMessage(fields, tts)
        elif fields["message"].startswith("TCP Connection") or fields[
            "message"
        ].startswith("TLS Connection"):
            if "uuid" in fields:
                msg = TCPMessage(
                    fields["message"],
                    (fields.get("local-address"), fields.get("local-port")),
                    (fields.get("remote-address"), fields.get("remote-port")),
                    tts,
                    fields.get("detail"),
                    fields.get("uuid"),
                )
            else:
                msg = TCPMessage(
                    fields["message"],
                    (fields.get("local-address"), fields.get("local-port")),
                    (fields.get("remote-address"), fields.get("remote-port")),
                    tts,
                    fields.get("detail"),
                )
                key = f"{msg.local[0]}:{msg.local[1]}.{msg.remote[0]}:{msg.remote[1]}"
                if key in tcpmsgs:
                    tcpmsgs[key].append(msg)
                else:
                    tcpmsgs[key] = [msg]
        else:
            continue

        if msg.call is None:
            continue

        add_msg_to_calls(msg, calls, host)

    add_msgs_to_calls(coalesce_fragments(fragments.values()), calls)

    for call in calls.values():
        conversation_id = call.admin.get("conversation-id")
        participant_id = call.admin.get_list("participant-id")
        if conversation_id and participant_id:
            conversation_map[conversation_id].update(set(participant_id))

    for call_id in list(calls):
        if call_id in call_map:
            parent_id = call_map[call_id]
            if call_id != parent_id:
                calls[parent_id].msgs.extend(calls[call_id].msgs)
                del calls[call_id]
        elif not calls[call_id].msgs:
            del calls[call_id]
        else:
            calls[call_id].add_tcpmsgs(tcpmsgs)

    # output calls sorted by first message timestamp
    for call in sorted(calls.values(), key=lambda call: call.start_tts):
        call.tidy_msgs()
        init_msg = call.get_init()
        if not init_msg:
            # skip incomplete call logs
            continue

        if filter_name and not isinstance(init_msg, H245Message):
            if (
                filter_name not in init_msg.from_addr.upper()
                and filter_name not in init_msg.to_addr.upper()
            ):
                continue

        if (
            protocol_filter
            and call.admin.get("Protocol", "").upper() not in protocol_filter
        ):
            continue

        if (
            no_spam
            and init_msg.user_agent
            and ("sipcli" in init_msg.user_agent or "pplsip" in init_msg.user_agent)
        ):
            continue

        call.to_text(fo)


if __name__ == "__main__":
    try:
        main()
    except (OSError, KeyboardInterrupt):
        pass
