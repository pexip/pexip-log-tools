#!/usr/bin/env zsh

# Copyright 2023 Pexip AS
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

# Pexip Log Tools for OSX
#
# https://docs.pexip.com/admin/log_tools.htm
# 
# Run; zsh -c "$(curl -sSL https://dl.pexip.com/resources/tools/sync_pexscripts.sh)"
#
# Ask for the admin password upfront.
sudo -v

# Create local storage directory & download Pexip scripts.
# Set Pexip script array
declare -a arr=("confhistory.py" "connectivity.py" "dbsummary.py" "logreader.py" "pexauthconfig.py" "pexidpconfig.py" "pexsnap.py" "pexwebapps.py" "mjxsummary.py" "staticroutes.py" "sync_pexscripts.sh")

# Create local directory
if [[ ! -e ~/pexscripts ]]; then
    mkdir ~/pexscripts
fi

# Backup previous versions of scripts in the array
for i in "${arr[@]}"
do
    if [ -f ~/pexscripts/$i ]; then
        chown -HR $USER ~/pexscripts/$i.old
        sudo cp ~/pexscripts/$i ~/pexscripts/$i.old
    fi
done

# Download scripts
echo 'Downloading Pexip py3 scripts...'
curl --silent -L -o ~/pexscripts/confhistory.py https://raw.githubusercontent.com/pexip/pexip-log-tools/master/confhistory.py
curl --silent -L -o ~/pexscripts/connectivity.py https://raw.githubusercontent.com/pexip/pexip-log-tools/master/connectivity.py
curl --silent -L -o ~/pexscripts/dbsummary.py https://raw.githubusercontent.com/pexip/pexip-log-tools/master/dbsummary.py
curl --silent -L -o ~/pexscripts/logreader.py https://raw.githubusercontent.com/pexip/pexip-log-tools/master/logreader.py
curl --silent -L -o ~/pexscripts/mjxsummary.py https://raw.githubusercontent.com/pexip/pexip-log-tools/master/mjxsummary.py
curl --silent -L -o ~/pexscripts/staticroutes.py https://raw.githubusercontent.com/pexip/pexip-log-tools/master/staticroutes.py
curl --silent -L -o ~/pexscripts/pexauthconfig.py https://raw.githubusercontent.com/pexip/pexip-log-tools/master/pexauthconfig.py
curl --silent -L -o ~/pexscripts/pexidpconfig.py https://raw.githubusercontent.com/pexip/pexip-log-tools/master/pexidpconfig.py
curl --silent -L -o ~/pexscripts/pexsnap.py https://raw.githubusercontent.com/pexip/pexip-log-tools/master/pexsnap.py
curl --silent -L -o ~/pexscripts/pexwebapps.py https://raw.githubusercontent.com/pexip/pexip-log-tools/master/pexwebapps.py
curl --silent -L -o ~/pexscripts/sync_pexscripts.sh https://raw.githubusercontent.com/pexip/pexip-log-tools/master/sync_pexscripts.sh

# First time setup
if [ ! -f ~/pexscripts/.sync_pexscripts_v3 ]; then
    code_installed=0

    if [ -f ~/pexscripts/.sync_pexscripts ]; then
        sudo rm -f ~/pexscripts/.sync_pexscripts
    fi
    # Create run folder, symbolic links and make them executable
    echo 'Creating links & making scripts executable...'
    if [[ ! -e /usr/local/bin ]]; then
        sudo mkdir /usr/local/bin
    fi
    for i in "${arr[@]}"
    do
        # If file exsits don't remove previous py2 symlinks
        if [ ! -f ~/pexscripts/.sync_pexscripts_v3 ]; then
            sudo rm -f /usr/local/bin/$i
        fi
        # remove .py extension from the symlink
        sudo ln -sf ~/pexscripts/$i /usr/local/bin/${i%.py}
        sudo chmod +x ~/pexscripts/$i && sudo chown -HR $USER /usr/local/bin/${i%.py}
    done

    # Add script update to cron
    echo 'Adding run job to cron...'
    crontab -l | grep -v 'pexscripts' > ~/pexscripts/.cron
    echo "# Download pexscripts (10:00 Mon-Fri)" >> ~/pexscripts/.cron
    echo "5 10 * * * ~/pexscripts/sync_pexscripts.sh >/dev/null 2>&1" >> ~/pexscripts/.cron
    crontab ~/pexscripts/.cron
    rm -f ~/pexscripts/.cron && touch ~/pexscripts/.sync_pexscripts_v3

    # Check for Homebrew & install if we don't have it
    if [[ $(which -s brew) == "brew not found" ]] ; then
        echo "Installing homebrew..."
        sudo rm -rf /Library/Developer/CommandLineTools
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    fi

    # Ask the user if they would like to install VSCode
    if [[ $(which brew) == "/opt/homebrew/bin/brew" ]] ; then
        echo "Install VSCode via brew?"
        select yn in "Yes" "No"; do
            case $yn in
                Yes ) 
                    echo 'Installing VSCode...'
                    /opt/homebrew/bin/brew update && /opt/homebrew/bin/brew upgrade
                    /opt/homebrew/bin/brew install --appdir="/Applications" --cask visual-studio-code
                    curl --silent -L -o ~/pexscripts/vsc-pexiplogs-extension-latest.vsix https://github.com/darrengoulden/vsc-pexiplogs-extension/releases/download/latest/vsc-pexiplogs-extension-latest.vsix
                    /Applications/Visual\ Studio\ Code.app/Contents/Resources/app/bin/code --install-extension ~/pexscripts/vsc-pexiplogs-extension-latest.vsix
                    code_installed=1;
                    break;;
                No )
                    break;;
            esac
        done
    fi

    # Check for pip3 & install if we don't have it so we can install lxml (required for logreader)
    if [[ $(which -s pip3) == "pip3 not found" ]] ; then
        echo 'Installing pip3 & lxml...'
        curl https://bootstrap.pypa.io/get-pip.py -o ~/pexscripts/get-pip.py
        python3 ~/pexscripts/get-pip.py
    fi
    python3 -m pip install --upgrade --user pip
    python3 -m pip install --user lxml
    python3 -m pip install --user pyOpenSSL
    python3 -m pip install --user dnspython
fi

# Set permissions
if [[ ! $EUID -ne 0 ]]; then
    chown -HR $SUDO_USER ~/pexscripts && chmod 700 ~/pexscripts
else
    chown -HR $USER ~/pexscripts && chmod 700 ~/pexscripts
fi
# chmod
for i in "${arr[@]}"
do
    sudo ln -sf ~/pexscripts/$i /usr/local/bin/${i%.py}
    sudo chmod +x ~/pexscripts/$i && sudo chown -RH $USER /usr/local/bin/${i%.py}
done
echo 'Done'

if [[ $code_installed -eq 1 ]]; then
    echo '***'
    echo 'Follow the README to complete the configuration of the VSCode syntax highlighting'
    echo 'https://github.com/darrengoulden/vsc-pexiplogs-extension/'
    echo '***';
fi
# Rehash the shell
sleep 2 && exec zsh && rehash
