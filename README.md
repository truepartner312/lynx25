Lynx Core 25.x integration/staging tree
=======================================

https://getlynx.io


How do I build the software?
----------------------------

At a minimum, the following dependencies should be present for Debian 12:

    #!/bin/bash
    echo "en_US.UTF-8 UTF-8" | tee -a /etc/locale.gen
    locale-gen en_US.UTF-8
    apt-get update -y && apt-get upgrade -y && apt-get dist-upgrade -y
    apt install build-essential make automake curl htop git libtool binutils bsdmainutils pkg-config python3 patch bison -y

The most troublefree and reproducable method of building the repository is via the depends method:

    git clone https://github.com/getlynx/lynx_25.x
    cd lynx_25.x/depends
    make HOST=<arch>
    cd ..
    ./autogen.sh
    CONFIG_SITE=$PWD/depends/<arch>/share/config.site ./configure
    make

Where <arch> can be replaced by one of the following:

    i686-pc-linux-gnu for Linux 32 bit
    x86_64-pc-linux-gnu for x86 Linux
    x86_64-w64-mingw32 for Win64
    x86_64-apple-darwin for macOS
    arm64-apple-darwin for ARM macOS
    arm-linux-gnueabihf for Linux ARM 32 bit
    aarch64-linux-gnu for Linux ARM 64 bit
    powerpc64-linux-gnu for Linux POWER 64-bit (big endian)
    powerpc64le-linux-gnu for Linux POWER 64-bit (little endian)
    riscv32-linux-gnu for Linux RISC-V 32 bit
    riscv64-linux-gnu for Linux RISC-V 64 bit
    s390x-linux-gnu for Linux S390X
    armv7a-linux-android for Android ARM 32 bit
    aarch64-linux-android for Android ARM 64 bit
    x86_64-linux-android for Android x86 64 bit

