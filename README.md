# Pexip Log Tools
Pexip log processing tools, for processing logs and databases into easy-to-read formats.

 * `confhistory.py` - Processes history databases from a diagnostic snapshot into summary of past conferences and calls.
 * `connectivity.py` - Processes administrator logs and configuration database from a diagnostic snapshot into summary of connectivity loss events.
 * `dbsummary.py` - Processes databases in a diagnostic snapshot into summary of key configuration information.
 * `Get-PexScripts.ps1` - Checks this repository for file updates and synchronises Pexip Log Tools on a user's PC
 * `logreader.py` - Processes support logs into log summaries for each call.
 * `mjxsummary.py` - Processes configuration database from a diagnostic snapshot and generates a summary of One Touch Join config
 * `Pexip_Log_Tools.ps1` - Processes an entire diagnostic snapshot and automatically generates dbsummary, confhistory, connectivity, mjxsummary and logreader reports.
 * `pexsnap.py` - ` - Processes an entire diagnostic snapshot and automatically generates dbsummary, confhistory, connectivity, mjxsummary and logreader reports (OSX).
 * `pexwebapps.py` - Processes configuration database from a diagnostic snapshot into summary of Web App config
 * `staticroutes.py` - Processes configuration database from a diagnostic snapshot into summary of conferencing node's static routes
 * `sync_pexscripts.sh` - Checks this repository for file updates and synchronises Pexip Log Tools on a user's PC (OSX).
 * `teamsload.py` - Processes history databases from a diagnostic snapshot if Teams Connector Enhanced Status is enabled ( Azure Event Hub )  and generates a utilization report of Teams Connector instances
 