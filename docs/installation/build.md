---
title: Local build
parent: Installation
nav_order: 23
---

# Building slipstream locally

To build slipstream locally on debian-based distros, you need the following dependencies installed:

* meson
* cmake
* git
* pkg-config
* libssl-dev
* ninja-build
* clang (or GCC)

Clone the slipstream repo and its submodules recursively.
This fetches slipstream, [brotili](https://github.com/google/brotli), [SPCDNS](https://github.com/spc476/SPCDNS), [lua-resty-base-encoding](https://github.com/spacewander/lua-resty-base-encoding), and our [picoquic fork](https://github.com/EndPositive/slipstream-picoquic/).

```shell
$ git clone --recurse-submodules https://github.com/EndPositive/slipstream.git
```

You can then configure slipstream by running the following command:

```shell
# Configure Meson with debug support (for project developers)
$ meson setup build
# OR for a build with full optimization (recommended for end-users)
$ meson setup --buildtype=release -Db_lto=true --warnlevel=0 build
# Build the client and server binaries
$ meson compile -C build
```

This will place the client and server binaries in the `build/` directory.
OpenSSL and other libraries (e.g. GNU C and C++) are dynamically linked into the binary by default where possible.


To enable static linking in as many libraries as possible:

```shell
# Add default_library=static option when building
$ meson setup -Ddefault_library=static ... build
```

A logging library exists within picoquic and may be enabled with a meson build option for debugging:

```shell
# Configure full logging
$ meson setup -Dbuild_loglib=true ... build
```
