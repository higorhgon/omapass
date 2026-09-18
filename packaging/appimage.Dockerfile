# The environment the portable build happens in. Ubuntu LTS on purpose: an
# AppImage only runs where glibc is at least as new as the one it was built
# against, so building on something newer would narrow who can run it.
#
# It exists as an image so the dependencies are installed once instead of on
# every `make appimage`.
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends \
        build-essential cmake pkg-config git curl ca-certificates file \
        desktop-file-utils \
        qmake6 qt6-base-dev qt6-declarative-dev qt6-tools-dev qt6-wayland \
        qml6-module-qtquick qml6-module-qtquick-controls \
        qml6-module-qtquick-templates qml6-module-qtquick-window \
        qml6-module-qtquick-dialogs qml6-module-qtquick-shapes \
        qml6-module-qtquick-layouts qml6-module-qt-labs-platform \
        qml6-module-qtqml-workerscript \
        libgl-dev libbotan-2-dev zlib1g-dev libminizip-dev libpcsclite-dev \
        libusb-1.0-0-dev libreadline-dev libxkbcommon-dev \
    && rm -rf /var/lib/apt/lists/*
