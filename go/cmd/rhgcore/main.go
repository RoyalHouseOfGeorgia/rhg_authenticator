// Command rhgcore is the RHG Authenticator core as a C library for native
// front ends (built with -buildmode=c-archive or c-shared). It exports the
// service/rpc JSON method surface through four C functions (exports.go):
//
//	char* RHGCall(char* method, char* paramsJSON);
//	void  RHGFree(char* p);
//	void  RHGSetEventCallback(rhg_event_cb cb);
//	int   RHGMainCLI(int argc, char** argv);
//
// The rhgfake build (-tags rhgfake) signs with a software card and never
// reaches GitHub or the production registry, for tests of a front end
// through the C ABI; its version string ends in " (rhgfake)".
package main

// main is unused: a c-archive or c-shared build needs a main package.
func main() {}
