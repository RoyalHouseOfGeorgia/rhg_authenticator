// The rhgcore C ABI, from the cgo-generated librhgcore.h of the library
// variant in RHGCORE_LIB_DIR (Package.swift puts that directory on the header
// search path). Including the generated header, rather than redeclaring the
// exports, makes a changed signature a compile error.
#include "librhgcore.h"
