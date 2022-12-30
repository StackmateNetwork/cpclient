#!/bin/bash -e
# Android SDK without Android Studio
# https://proandroiddev.com/how-to-setup-android-sdk-without-android-studio-6d60d0f2812a

export ANDROID_NDK_HOME=/home/ishi/android/ndk/21.4.7075529

echo $REPO
if (( $EUID == 0 )); then
    REPO="/cpclient"
else
    REPO=$(dirname $(pwd))
fi

cd $REPO && make android
cargo build --release

TARGET_DIRECTORY="$REPO/target"
BUILDS_DIRECTORY="$REPO/builds"

mkdir -p $BUILDS_DIRECTORY/x86_64-apple-darwin

mkdir -p $BUILDS_DIRECTORY/aarch64-linux-android
mkdir -p $BUILDS_DIRECTORY/x86_64-linux-android
mkdir -p $BUILDS_DIRECTORY/i686-linux-android
mkdir -p $BUILDS_DIRECTORY/armv7-linux-androideabi

mkdir -p $BUILDS_DIRECTORY/x86_64-linux-unknown

cp $TARGET_DIRECTORY/aarch64-linux-android/release/libcpclient.so $BUILDS_DIRECTORY/aarch64-linux-android/
cp $TARGET_DIRECTORY/x86_64-linux-android/release/libcpclient.so $BUILDS_DIRECTORY/x86_64-linux-android/
cp $TARGET_DIRECTORY/i686-linux-android/release/libcpclient.so $BUILDS_DIRECTORY/i686-linux-android/
cp $TARGET_DIRECTORY/armv7-linux-androideabi/release/libcpclient.so $BUILDS_DIRECTORY/armv7-linux-androideabi/
cp $TARGET_DIRECTORY/release/libcpclient.so $BUILDS_DIRECTORY/x86_64-linux-unknown/

exit