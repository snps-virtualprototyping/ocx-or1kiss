# OpenCpuX/or1kiss - Open Source Instruction-Set Simulation Integration Kit

## Overview

This is an adaptation of the [OpenRisc 1000 Core](https://github.com/janweinstock/or1kiss)
to run as a core model using the [OpenCpuX API](https://github.com/snps-virtualizer/ocx).

## How to build

* Clone the repository and `cd` into the repository
* Initialize and update the submodules:

        git submodule init
        git submodule update --init --recursive

* Create a `BUILD` directory

        mkdir BUILD
        cd BUILD

* Run [CMake](https://cmake.org), then `make` to build both the test harness 
  and the or1kiss core

        cmake ..
        make

* The module should pass the regression tests are specified by the ocx test 
  harness:

        make test

        Running tests...
        Test project /localdev/tobies/ocx/ocx-or1kiss/BUILD
        Start 1: ocx-or1kiss
        1/2 Test #1: ocx-or1kiss ......................   Passed    0.14 sec
        Start 2: smoke
        2/2 Test #2: smoke ............................   Passed    0.01 sec

        100% tests passed, 0 tests failed out of 2


