#!/bin/bash
SERVER=debian@scb
SERVER_DIRECTORY=/home/debian/cpclient/builds
rm -rf ../builds
scp -r "$SERVER:$SERVER_DIRECTORY" ../
# tar -czvf releases.tar ../builds