#!/usr/bin/env zsh

# Copyright 2025 Pexip AS
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

# Pexip scripts directory
PEX_DIR=~/pexscripts

# Pexip script array
declare -a PEX_SCRIPTS=("confhistory.py" "connectivity.py" "dbsummary.py" "logreader.py" "pexauthconfig.py" "pexidpconfig.py" "pexsnap.py" "pexwebapps.py" "mjxsummary.py" "staticroutes.py" "sync_pexscripts.sh")

# Enable debug output
DEBUG=0

#####################################################################
CURRENT_VERSION=v4
SHELL_BIN=`echo $SHELL`

# Check for debug flag
if [ "$DEBUG" = "1" ]; then
    set -x
else
    set +x
fi

function print_step() {
    echo "> $1"
}

function create_pexscripts_dir() {
    # Create the pexscripts directory
    if [[ ! -e $PEX_DIR ]]; then
        mkdir $PEX_DIR
    fi
}

function backup_pexscripts() {
    # Backup current versions of the Pexip scripts
    for i in "${PEX_SCRIPTS[@]}"
    do
        if [ -f $PEX_DIR/$i ]; then
            chown $USER $PEX_DIR/$i.old > /dev/null 2>&1
            cp -f $PEX_DIR/$i $PEX_DIR/$i.old
        fi
    done
}

function download_pexscripts() {
    # Download scripts from the Pexip GitHub repo
    print_step 'Downloading Pexip scripts...'
    for i in "${PEX_SCRIPTS[@]}"
    do
        curl --silent -L -o $PEX_DIR/$i https://raw.githubusercontent.com/pexip/pexip-log-tools/master/$i
    done
}

function first_run_add_cron() {
    # Add script update to cron
    print_step 'Adding a script update job to cron...'
    crontab -l | grep -v 'pexscripts' > $PEX_DIR/.cron > /dev/null 2>&1
    echo "# Download pexscripts (10:00 Mon-Fri)" >> $PEX_DIR/.cron
    echo "5 10 * * * $PEX_DIR/sync_pexscripts.sh >/dev/null 2>&1" >> $PEX_DIR/.cron
    crontab $PEX_DIR/.cron
    rm -f $PEX_DIR/.cron && touch $PEX_DIR/.sync_pexscripts_$CURRENT_VERSION
}

function install_xcode() {
    # Check for Xcode Command Line Tools & install if we don't have it
    print_step "Command Line Tools for Xcode not found. Installing from softwareupdate…"
    # This temporary file prompts the 'softwareupdate' utility to list the Command Line Tools
    touch /tmp/.com.apple.dt.CommandLineTools.installondemand.in-progress;
    PROD=$(softwareupdate -l | grep "\*.*Command Line" | tail -n 1 | sed 's/^[^C]* //')
    softwareupdate -i "$PROD" --verbose;
}

function install_homebrew() {
    # Check for Homebrew & install if we don't have it
    print_step "Installing Homebrew package manager..."
    sudo rm -rf /Library/Developer/CommandLineTools
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    BREW_INSTALLED=1;
}

function install_vscode() {
    # Install VSCode
    print_step 'Installing Visual Studio Code...'
    /opt/homebrew/bin/brew update && /opt/homebrew/bin/brew upgrade
    /opt/homebrew/bin/brew install --appdir="/Applications" --cask visual-studio-code
    curl --silent -L -o $PEX_DIR/vsc-pexiplogs-extension-latest.vsix https://github.com/darrengoulden/vsc-pexiplogs-extension/releases/download/latest/vsc-pexiplogs-extension-latest.vsix
    /Applications/Visual\ Studio\ Code.app/Contents/Resources/app/bin/code --install-extension $PEX_DIR/vsc-pexiplogs-extension-latest.vsix
}

function first_run_remove_old_lock_file() {
    # Remove the old pexscripts lock file
    if [ -f $PEX_DIR/.sync_pexscripts ]; then
        rm -f $PEX_DIR/.sync_pexscripts
    fi
}

function first_run_link_pexscripts() {
    # Create run folder, symbolic links and make them executable
    print_step 'Creating links & making scripts executable...'
    if [[ ! -e /usr/local/bin ]]; then
        sudo mkdir /usr/local/bin
    fi
    for i in "${PEX_SCRIPTS[@]}"
    do
        # Remove the old symlink if the lock file is missing
        if [ ! -f $PEX_DIR/.sync_pexscripts_$CURRENT_VERSION ]; then
            sudo rm -f /usr/local/bin/$i
        fi
        # remove .py extension from the symlink
        if [[ $i =~ 'pexsnap.py' ]]; then
            if [ ! -f /usr/local/bin/${i%.py} ]; then
                sudo touch /usr/local/bin/${i%.py}
            fi
            sudo chmod +x $PEX_DIR/$i && sudo chown $USER /usr/local/bin/${i%.py}
            continue
        fi
        sudo ln -sf $PEX_DIR/$i /usr/local/bin/${i%.py}
        sudo chmod +x $PEX_DIR/$i && sudo chown $USER /usr/local/bin/${i%.py}
    done
}

function first_run_create_and_setup_venv() {
    # Create and setup the virtual environment
    print_step 'Creating and setting up the virtual environment...'
    cd $PEX_DIR
    python3 -m venv .venv
    source .venv/bin/activate > /dev/null 2>&1
    if [[ "$VIRTUAL_ENV" != "" ]]; then
        print_step 'Virtual environment created successfully!'
        print_step 'Upgrading pip...'
        python3 -m ensurepip --upgrade
        python3 -m pip install --upgrade pip
        print_step 'Installing python dependencies...'
        python3 -m pip install lxml
        python3 -m pip install pyOpenSSL
        python3 -m pip install dnspython
        deactivate
    else
        print_step 'Error creating virtual environment!'
        exit 1
    fi
    cd -
}

function first_run_create_run_scripts() {
    # Create the run scripts
    for i in "${PEX_SCRIPTS[@]}"
    do
        if [ -f /usr/local/bin/${i%.py} ]; then
            sudo rm -f /usr/local/bin/${i%.py}
        fi
        sudo tee /usr/local/bin/${i%.py} &>/dev/null <<EOF
#!$SHELL_BIN
# Activate the virtual environment
source $PEX_DIR/.venv/bin/activate

# Run the Python script
if [[ "\$VIRTUAL_ENV" != "" ]]; then
    $PEX_DIR/.venv/bin/python $PEX_DIR/$i "\$@"
else
    echo "Error activating virtual environment!"
    exit 1
fi

# Deactivate the virtual environment
deactivate
EOF
        sudo chmod +x /usr/local/bin/${i%.py}
        sudo chown $USER /usr/local/bin/${i%.py}
    done
}

function update_zshrc_using_tee(){
    # Update the .zshrc file
    tee -a ~/.zshrc &>/dev/null <<EOF
# Automatically activate Python venv if it exists
auto_snapshot_venv() {
    if [[ "\$PWD" =~ ^$snap_dir ]]; then
        source $PEX_DIR/.venv/bin/activate
    elif [ "\$VIRTUAL_ENV" != "" ] && [[ ! -e "\$PWD/.venv" || ! -e "\$PWD/venv" ]]; then
        deactivate
    fi
}

# Override the 'cd' command to call our function
cd() {
    builtin cd "\$@" && auto_snapshot_venv
}
EOF
}

function first_run_update_zshrc() {
    # Update the .zshrc file
    while :; do
        print_step "Enter the path to the snapshot directory:"
        read directory

        # Check if the directory is a tilde path
        if [[ $directory == "~"* ]]; then
            snap_dir="${directory/#\~/$HOME}"
        else
            snap_dir="$PWD/$directory"
        fi

        if [ -d "$snap_dir" ]; then
            update_zshrc_using_tee
            break
        else
            print_step "$snap_dir does not exist, create it?"
            select yn in "Yes" "No"; do
                case $yn in
                    Yes )
                        print_step "Creating directory: $snap_dir"
                        mkdir -p $snap_dir
                        update_zshrc_using_tee
                        break;;
                    No )
                        print_step "Exiting..."
                        break;;
                esac
            done
            break
        fi
    done
}

function set_permissions() {
    # Set permissions on PEX_DIR
    if [[ ! $EUID -ne 0 ]]; then
        chown -HR $SUDO_USER $PEX_DIR && chmod 700 $PEX_DIR
    else
        chown -HR $USER $PEX_DIR && chmod 700 $PEX_DIR
    fi
}

function create_links_and_set_x() {
    # Create links and make scripts executable
    for i in "${PEX_SCRIPTS[@]}"
    do
        if [[ $i =~ 'pexsnap.py' ]]; then
            if [ ! -f /usr/local/bin/${i%.py} ]; then
                sudo touch /usr/local/bin/${i%.py}
            fi
            sudo chmod +x $PEX_DIR/$i && sudo chown $USER /usr/local/bin/${i%.py}
            continue
        fi
        sudo ln -sf $PEX_DIR/$i /usr/local/bin/${i%.py}
        sudo chmod +x $PEX_DIR/$i && sudo chown $USER /usr/local/bin/${i%.py}
    done
}

### START ###
# Create the pexscripts directory
create_pexscripts_dir
# Backup current versions of the Pexip scripts
backup_pexscripts
# Download scripts from the Pexip GitHub repo
download_pexscripts
# Check for existing v3 environment and migrate to venv
if [ -f $PEX_DIR/.sync_pexscripts_v3 ]; then
    if [ ! -d $PEX_DIR/.venv ]; then
        print_step 'Migrating to venv...'
        first_run_create_and_setup_venv
        first_run_create_run_scripts
        print_step "Update .zshrc file to automatically activate venv?"
        select yn in "Yes" "No"; do
            case $yn in
                Yes ) 
                    first_run_update_zshrc
                    break;;
                No )
                    break;;
            esac
        done
        touch $PEX_DIR/.sync_pexscripts_$CURRENT_VERSION
        rm -f $PEX_DIR/.sync_pexscripts_v3
        print_step 'Migration complete!'
        exit 0;
    fi
fi
# First time setup? Check for lock file...
if [ ! -f $PEX_DIR/.sync_pexscripts_$CURRENT_VERSION ]; then
    BREW_INSTALLED=0
    # Remove the old pexscripts lock file
    first_run_remove_old_lock_file
    # Create run folder, symbolic links and make them executable
    first_run_link_pexscripts
    # Add script update to cron
    first_run_add_cron
    # Check for Homebrew & provide option to install
    if [[ $(which -s brew) == "brew not found" ]] ; then
        print_step "Install Homebrew package manager?"
        select yn in "Yes" "No"; do
            case $yn in
                Yes ) 
                    install_homebrew
                    break;;
                No )
                    break;;
            esac
        done
    fi
    # Check for Xcode Command Line Tools & install if MacOS
    if [[ $(uname) == 'Darwin' ]]; then
        xcode-select -p &> /dev/null
        if [ $? -ne 0 ]; then
            install_xcode
        fi
    fi
    # Ask the user if they would like to install VSCode
    if [[ -f /opt/homebrew/bin/brew ]]; then
        if [[ $(which -s code) == "code not found" ]] ; then
            print_step "Install Visual Studio Code?"
            select yn in "Yes" "No"; do
                case $yn in
                    Yes ) 
                        install_vscode
                        break;;
                    No )
                        break;;
                esac
            done
        fi
    fi

    # Create the virtual environment and install dependencies
    first_run_create_and_setup_venv
    # Create the run script
    first_run_create_run_script
    # Update the .zshrc file
    print_step "Update .zshrc file to automatically activate venv?"
    select yn in "Yes" "No"; do
        case $yn in
            Yes ) 
                first_run_update_zshrc
                break;;
            No )
                break;;
        esac
    done
fi

# Set permissions
set_permissions
# Create symlinks and set executable
create_links_and_set_x

# Finished
print_step 'Sync complete!'
# Rehash the shell
sleep 2 && exec $SHELL_BIN && rehash

exit 0;
