A groovy modbus library
=======================

[![Build Status](https://travis-ci.org/stephane/libmodbus.svg?branch=master)](https://travis-ci.org/stephane/libmodbus)

Overview
--------

libmodbus is a free software library to send/receive data with a device which
respects the Modbus protocol. This library can use a serial port or an Ethernet
connection.

The functions included in the library have been derived from the Modicon Modbus
Protocol Reference Guide which can be obtained from Schneider at
[www.schneiderautomation.com](http://www.schneiderautomation.com).

The license of libmodbus is *LGPL v2.1 or later*.

The documentation is available as manual pages (`man libmodbus` to read general
description and list of available functions) or Web pages
[www.libmodbus.org/documentation/](http://libmodbus.org/documentation/). The
documentation is licensed under the Creative Commons Attribution-ShareAlike
License 3.0 (Unported) (<http://creativecommons.org/licenses/by-sa/3.0/>).

The official website is [www.libmodbus.org](http://www.libmodbus.org).

The library is written in C and designed to run on Linux, Mac OS X, FreeBSD and
QNX and Windows.

Installation
------------

You will only need to install CMake (3.0 or higher) and a C compiler to compile
the library and asciidoc and xmlto to generate the documentation (optional).

To install, the recommended way is to create a out-of-tree build-dir somewhere
out of the source tree and run `cmake path/to/libmodbus/ && make`. Or with ninja
`cmake path/to/libmodbus -GNinja && make`.

You can change installation directory by setting the `CMAKE_INSTALL_PREFIX`-
variable at CMake-configure time (inside the build-dir):

    cmake -DCMAKE_INSTALL_PREFIX=/usr -GNinja path/to/libmodbus
	ninja install

By default a shared-library is build, this can be toggled with the
`BUILD_SHARED_LIBS`-variable

    cmake -DBUILD_SHARED_LIBS=OFF <...>

Building in with compiler-debug-options or release-options can be done by
specifying `CMAKE_BUILD_TYPE`:

    cmake -DCMAKE_BUILD_TYPE=Release|Debug

You have to check that the installation library path is properly set up on your
system (*/etc/ld.so.conf.d*) and library cache is up to date
(run `ldconfig` as root if required).

The library provides a *libmodbus.pc* file to use with `pkg-config` to ease your
program compilation and linking.

The library also provides a `cmake/libmodbusConfig.cmake` which, after
installation should allow you to include the libmodbus-library
(including its include-paths) in your CMake-based project.

If you want to compile with Microsoft Visual Studio, use cmake for Windows.
It will generate a VCProject-file or NMake-files. You may need to install
<https://github.com/chemeris/msinttypes> to fill the absence of stdint.h.

To compile under OS X with [homebrew](http://mxcl.github.com/homebrew/) should
work seemlessly as homebrew supports CMake.

Documentation
-------------

The documentation is available [online](http://libmodbus.org/documentation) or
as manual pages after installation.

The documentation is based on
[AsciiDoc](http://www.methods.co.nz/asciidoc/).

To build the man-pages and/or the html-documentation you need to enable the CMake option
`BUILD_DOCS` and `BUILD_DOCS_HTML`, `BUILD_DOCS_MAN` respectively. If enabled the generated
man-pages will be installed.

If the necessary tools to build the documentation are not detected by cmake, these variables
are forced to off.

    cmake -DCMAKE_INSTALL_PREFIX=/usr -GNinja path/to/libmodbus -DBUILD_DOCS=ON
	ninja doc
	ninja install

Testing
-------

Some tests are provided in *tests* directory, you can freely edit the source
code to fit your needs (it's Free Software :).

See *tests/README* for a description of each program.

Tests are built by default, but this can be disable by setting the variable
`BUILD_TESTING` to OFF.

For a quick manual test of libmodbus, you can run the following programs in two shells:

1. ./unit-test-server
2. ./unit-test-client

By default, all TCP unit tests will be executed (see --help for options).

It's also possible to run the unit tests with ctest:

    cmake -GNinja path/to/libmodbus
	ninja
    ctest

To report a bug or to contribute
--------------------------------

See [CONTRIBUTING](CONTRIBUTING.md) document.
