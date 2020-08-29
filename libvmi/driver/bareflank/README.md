# LibVMI with Bareflank Boxy / MicroV

The Bareflank hypervisor has some very interesting properties. One of which is its **late launch** feature that basically allows to demote the current running host OS into a VM, a feature also used by rootkits.
Bareflank Boxy / MicroV is an extension to the base hypervisor that adds multiple guest VM support.
With the support of Boxy / MicroV, LibVMI is able for the first time to introspect a host Windows OS. With the combination of late launch, interesting new type of LibVMI based security applications could emerge. e.g. Imagine a LibVMI based anti-virus that can just be deployed and installed on a host Windows OS. It doesn't require any complicated environment to be setup.

With Boxy / MicroV we will create a tiny Linux VM with the help of Buildroot. Buildroot is required to cross compile LibVMI with its dependencies and to setup a minimal environment and generate for us the `bzImage` and the `rootfs`. The LibVMI application will run as the only process `init`, i.e. there is no other user space application running in this environment. It is possible to change this by modifying the [buildroot config files](https://github.com/chp-io/boxy/tree/chp-gsoc20-final/examples/buildroot).

The previous implementation of the Bareflank driver only supported the base hypervisor with memory access and some register access. This newer implementation done during GSoC20, added MicroV / Boxy support, better register access and some events. The infrastructure for events now in place, it should be easy to implement the rest of them.

## Compilation Instructions

To generate the `bzImage` + `rootfs.cpio.gz` with buildroot we need a Linux machine. But first we need to generate a rekall profile for the target machine as you would normally for LibVMI to work. Once this is done, if Windows is the target, Bareflank will need to continue to be compiled on a Windows machine.

### Linux

#### Dependencies

On Ubuntu 18.04:

**Buildroot dependencies**:
```
sudo apt-get -q -y install build-essential libncurses5-dev \
    git bzr cvs mercurial subversion libc6:i386 unzip bc
```

**Bareflank dependencies**:
```
sudo apt-get -q -y install git build-essential linux-headers-$(uname -r) \
    nasm libelf-dev bison flex #clang #cmake
```

**Bareflank needs a newer cmake version**:
```
CMAKE_VERSION="cmake-3.17.3-Linux-x86_64"
mkdir /opt/cmake
cd /opt/cmake
wget -q -c "https://github.com/Kitware/CMake/releases/download/v3.17.3/${CMAKE_VERSION}.tar.gz"
tar xzf "${CMAKE_VERSION}.tar.gz"
echo "export PATH=/opt/cmake/${CMAKE_VERSION}/bin:\$PATH" > /etc/profile.d/cmake.sh
```

**Getting Buildroot**:
```
cd ~/
BUILDROOT_VERSION=2020.02.4
wget -q -c http://buildroot.org/downloads/buildroot-#{BUILDROOT_VERSION}.tar.gz
tar axf buildroot-${BUILDROOT_VERSION}.tar.gz
mv buildroot-${BUILDROOT_VERSION} buildroot
```

**Getting Boxy**:
```
git clone https://github.com/chp-io/boxy
cd boxy
git checkout chp-gsoc20-final
git submodule init
git submodule update
```

#### Compilation

Some buildroot options that can be changed for libvmi:

```
export BR2_LIBVMI_DEBUG=n
export BR2_LIBVMI_INCLUDE_EXAMPLES=y
export BR2_LIBVMI_PATH=<path_to_libvmi> # Helpful during development otherwise not needed

export REKALL_PROFILE_PATH=<path_to_rekall.json>
```

Buildroot:

```
cd ~/buildroot
make BR2_EXTERNAL=~/boxy/examples/buildroot vmilinux_defconfig
make
```

We now have our minimal Linux (vmilinux) generated buildroot in:

```
~/buildroot/output/images/{bzImage,rootfs.cpio.gz}
```

From here, if we want to target Windows, we need to follow the next Windows section to compile Boxy on Windows.

##### Linux target

We need to finally compile Boxy for Linux

```
cd ~/boxy
mkdir build && cd build
cmake ../hypervisor
make
```

Start the hypervisor with:

```
make driver_quick
make quick
```

Finally launch the vm with:

The singlestep example to showcase events:

```
./prefixes/x86_64-userspace-elf/bin/bfexec --bzimage --path ~/buildroot/output/images/bzImage --initrd ~/buildroot/output/images/rootfs.cpio.gz --uart=0x3f8 --verbose --size=0x8000000 --cmdline="vmi=/usr/bin/singlestep-event-example,dom0,none,1"
```

The process list example:

```
./prefixes/x86_64-userspace-pe/bin/bfexec.exe --bzimage --path ~/buildroot/output/images/bzImage --initrd ~/buildroot/output/images/rootfs.cpio.gz --uart=0x3f8 --verbose --size=0x8000000 --cmdline="vmi=/usr/bin/vmi-process-list,-n,dom0"
```


### Windows (cygwin)

The Linux section needs to be followed up until we have generated vmilinux in:
`~/buildroot/output/images/{bzImage,rootfs.cpio.gz}`

These two files need to be copied over. From cygwin create `BUILDROOT_IMAGES_PATH` set to the path where these files where copied over, this will be used later to launch the VM:

```
export BUILDROOT_IMAGES_PATH=<path_to_images_directory>
```

#### Dependencies

**Bareflank dependencies**:

Mostly following the [Bareflank readme](https://github.com/Bareflank/hypervisor/blob/master/README.md), gives us:

- [Visual Studio 2019 / WDK 10](https://docs.microsoft.com/en-us/windows-hardware/drivers/)
  - Check "Desktop development with C++"
  - Check "C++ CLI / Support"
  - Check "VC++ 2019 version xxx Libs for Spectre (x86 and x64)"

After installing the above packages, you must enable test signing mode. This can be done from a command prompt with admin privileges:
```
bcdedit.exe /set testsigning ON
<reboot>
```

- [Cygwin](https://www.cygwin.com/setup-x86_64.exe)

To install Cygwin, simply install using all default settings, and then copy
setup-x86\_64.exe to C:\\cygwin64\\bin. From there, open a Cygwin terminal and
run the following:

```
setup-x86_64.exe -q -P git,make,gcc-core,gcc-g++,nasm,clang,clang++,cmake,python,gettext,bash-completion,flex,bison,texinfo
```

**Getting Boxy**:

```
git clone https://github.com/chp-io/boxy
cd boxy
git checkout chp-gsoc20-final
git submodule init
git submodule update
```

#### Compilation

##### Windows target

Now we need to compile Boxy for Windows

```
cd ~/boxy
mkdir build && cd build
cmake ../hypervisor
make
```

Start the hypervisor with:

```
make driver_quick
make quick
```

Finally launch the VM with:

The singlestep example to showcase events:

```
./prefixes/x86_64-userspace-pe/bin/bfexec.exe --bzimage --path ${BUILDROOT_IMAGES_PATH}/bzImage --initrd ${BUILDROOT_IMAGES_PATH}/rootfs.cpio.gz --uart=0x3f8 --verbose --size=0x8000000 --cmdline="vmi=/usr/bin/singlestep-event-example,dom0,none,1"
```

The process list example:

```
./prefixes/x86_64-userspace-pe/bin/bfexec.exe --bzimage --path ${BUILDROOT_IMAGES_PATH}/bzImage --initrd ${BUILDROOT_IMAGES_PATH}/rootfs.cpio.gz --uart=0x3f8 --verbose --size=0x8000000 --cmdline="vmi=/usr/bin/vmi-process-list,-n,dom0"
```
