/*
 * Smoke test of the rhgcore C library through its C ABI, run by
 * scripts/rhgcore-smoke.sh on Linux, macOS and Windows (only the link line
 * differs).
 *
 *   smoke --version [...]          RHGMainCLI(argc, argv); exits with its code
 *   smoke <data-dir> release|fake  the checks below; "fake" adds the flows
 *                                  that need the rhgfake build
 *
 * Prints each check and exits non-zero on the first failure.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include "rhgcore.h"
#else
#include "librhgcore.h"
#endif

static int checks;
static volatile int events_seen;
static volatile int pins_submitted;

/* on_event counts events and answers a pin.request with the fake card's PIN
 * from inside the callback (pin.submit does not block). */
static void on_event(const char *json) {
	const char *id;
	char params[128];
	char *res;

	events_seen++;
	if (strstr(json, "\"event\":\"pin.request\"") == NULL) {
		return;
	}
	id = strstr(json, "\"requestId\":");
	if (id == NULL) {
		return;
	}
	snprintf(params, sizeof params, "{\"requestId\":%ld,\"pin\":\"123456\"}",
	         strtol(id + strlen("\"requestId\":"), NULL, 10));
	res = RHGCall("pin.submit", params);
	if (res != NULL && strstr(res, "\"ok\":true") != NULL) {
		pins_submitted++;
	}
	RHGFree(res);
}

static void fail(const char *what, const char *got) {
	printf("FAIL: %s\n  got: %s\n", what, got ? got : "(null)");
	fflush(stdout);
	exit(1);
}

static void pass(const char *what) {
	checks++;
	printf("ok: %s\n", what);
	fflush(stdout);
}

/* expect runs RHGCall and checks the response contains want1 and (unless
 * NULL) want2, then frees it. */
static void expect(const char *what, const char *method, const char *params,
                   const char *want1, const char *want2) {
	char *res = RHGCall((char *)method, (char *)params);
	if (res == NULL) {
		fail(what, NULL);
	}
	if (strstr(res, want1) == NULL || (want2 != NULL && strstr(res, want2) == NULL)) {
		fail(what, res); /* exits; the process frees res */
	}
	RHGFree(res);
	pass(what);
}

/* json_escape writes s as a JSON string body (escaping \ and ") to out. */
static void json_escape(const char *s, char *out, size_t size) {
	size_t n = 0;
	for (; *s != '\0' && n + 2 < size; s++) {
		if (*s == '\\' || *s == '"') {
			out[n++] = '\\';
		}
		out[n++] = *s;
	}
	out[n] = '\0';
}

int main(int argc, char **argv) {
	if (argc >= 2 && strcmp(argv[1], "--version") == 0) {
		int code = RHGMainCLI(argc, argv);
		fflush(stdout);
		return code;
	}
	if (argc != 3 || (strcmp(argv[2], "release") != 0 && strcmp(argv[2], "fake") != 0)) {
		fprintf(stderr, "usage: %s --version | %s <data-dir> release|fake\n", argv[0], argv[0]);
		return 2;
	}
	const char *data_dir = argv[1];
	int fake = strcmp(argv[2], "fake") == 0;

	char *version_argv[] = {"rhgcore", "--version", NULL};
	char *ui_argv[] = {"rhgcore", NULL};
	if (RHGMainCLI(2, version_argv) != 0) {
		fail("RHGMainCLI --version returns 0", "non-zero");
	}
	fflush(stdout);
	pass("RHGMainCLI --version returns 0");
	if (RHGMainCLI(1, ui_argv) != -1) {
		fail("RHGMainCLI without CLI args returns -1", "not -1");
	}
	if (RHGMainCLI(0, NULL) != -1) {
		fail("RHGMainCLI(0, NULL) returns -1", "not -1");
	}
	pass("RHGMainCLI without CLI args returns -1");

	expect("unknown method is an input error", "no.such.method", "{}", "\"ok\":false", "\"code\":\"input\"");
	expect("NULL method and params", NULL, NULL, "\"ok\":false", "\"code\":\"input\"");
	RHGFree(NULL);
	pass("RHGFree(NULL)");

	if (fake) {
		char escaped[4096];
		char params[4200];
		json_escape(data_dir, escaped, sizeof escaped);
		snprintf(params, sizeof params, "{\"dataDir\":\"%s\"}", escaped);

		RHGSetEventCallback(on_event);
		expect("test.configure offline", "test.configure", "{\"online\":false}", "\"ok\":true", NULL);
		expect("app.init", "app.init", params, "\"ok\":true", "\"online\":false");
		expect("sign.sign, PIN answered from the event callback", "sign.sign",
		       "{\"recipient\":\"Jane Doe\",\"honor\":\"Ennoblement\","
		       "\"detail\":\"For service\",\"date\":\"2026-01-02\"}",
		       "\"ok\":true", "\"url\":\"https://");
		if (pins_submitted != 1) {
			fail("one pin.request answered through the callback", "not exactly one");
		}
		pass("one pin.request answered through the callback");
		expect("test.panic is an internal error", "test.panic", "{}", "\"ok\":false", "\"code\":\"internal\"");
		expect("app.canQuit after a panic", "app.canQuit", NULL, "\"ok\":true", NULL);
		expect("app.shutdown", "app.shutdown", "{}", "\"ok\":true", NULL);
		RHGSetEventCallback(NULL);
		pass("RHGSetEventCallback(NULL)");
		printf("events received: %d\n", events_seen);
	}

	printf("PASS: %d checks (%s)\n", checks, fake ? "fake" : "release");
	return 0;
}
