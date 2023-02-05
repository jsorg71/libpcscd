#!/bin/sh

cd src
make $@
cd ..

cd test
make $@
cd ..
