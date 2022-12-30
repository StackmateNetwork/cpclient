#!/bin/bash
RELEASE_TAG=v0.1.1

if (( $EUID == 0 )); then
    REPO="/cpclient"
else
    REPO="$HOME/operator/TomaTech/CypherPost/Code/cpclient"
fi


cd $REPO
rm -rf $RELEASE_TAG.tar
tar -czf $RELEASE_TAG.tar.gz builds

