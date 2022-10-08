#!/bin/bash
RELEASE_TAG=v0.12.2

if (( $EUID == 0 )); then
    REPO="/cpclient"
else
    REPO="$HOME/StackmateNetwork/cpclient"
fi


cd $REPO
rm -rf $RELEASE_TAG.tar
tar -czf $RELEASE_TAG.tar.gz builds

