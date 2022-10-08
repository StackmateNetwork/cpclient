#!/bin/bash

source $HOME/.bashrc

if (( $EUID == 0 )); then
    bash /cpclient/scripts/build.sh
else
    bash $HOME/cpclient/scripts/build.sh
fi
# tail -f /dev/null

exec "$@"