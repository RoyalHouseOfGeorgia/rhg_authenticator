package safego

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"log"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const waitTimeout = 5 * time.Second

// setHandler installs h and restores the previous handler on cleanup.
func setHandler(t *testing.T, h func(r any, stack []byte)) {
	t.Helper()
	prev := handler
	SetPanicHandler(h)
	t.Cleanup(func() { SetPanicHandler(prev) })
}

// chanWriter forwards each write to a channel so tests can wait for log output.
type chanWriter struct{ ch chan string }

func (w chanWriter) Write(p []byte) (int, error) {
	w.ch <- string(p)
	return len(p), nil
}

// captureLog redirects the stdlib logger into a channel for the test's duration.
func captureLog(t *testing.T) <-chan string {
	t.Helper()
	ch := make(chan string, 4)
	prevOut, prevFlags := log.Writer(), log.Flags()
	log.SetOutput(chanWriter{ch: ch})
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(prevOut)
		log.SetFlags(prevFlags)
	})
	return ch
}

func waitLog(t *testing.T, ch <-chan string) string {
	t.Helper()
	select {
	case s := <-ch:
		return s
	case <-time.After(waitTimeout):
		t.Fatal("timed out waiting for log output")
		return ""
	}
}

func TestGo_RunsFunction(t *testing.T) {
	done := make(chan struct{})
	Go(func() { close(done) })
	select {
	case <-done:
	case <-time.After(waitTimeout):
		t.Fatal("fn did not run")
	}
}

func TestGo_RecoversPanicAndCallsHandler(t *testing.T) {
	type report struct {
		r     any
		stack []byte
	}
	got := make(chan report, 1)
	setHandler(t, func(r any, stack []byte) { got <- report{r, stack} })

	Go(func() { panic("boom") })

	select {
	case rep := <-got:
		if rep.r != "boom" {
			t.Errorf("panic value = %v, want boom", rep.r)
		}
		if len(rep.stack) == 0 {
			t.Error("stack is empty")
		}
		if len(rep.stack) > stackBufSize {
			t.Errorf("stack len %d exceeds %d", len(rep.stack), stackBufSize)
		}
		if !strings.Contains(string(rep.stack), "goroutine") {
			t.Errorf("stack does not look like a stack trace: %q", rep.stack)
		}
	case <-time.After(waitTimeout):
		t.Fatal("handler not called")
	}
}

func TestGo_PanickingHandlerFallsBackToDefault(t *testing.T) {
	logCh := captureLog(t)
	setHandler(t, func(any, []byte) { panic("handler broke") })

	Go(func() { panic("original") })

	msg := waitLog(t, logCh)
	if !strings.Contains(msg, "PANIC (goroutine): original") {
		t.Errorf("log missing original panic: %q", msg)
	}
	if !strings.Contains(msg, "handler broke") {
		t.Errorf("log missing handler panic: %q", msg)
	}
}

func TestGo_DefaultHandlerWhenUnset(t *testing.T) {
	logCh := captureLog(t)
	setHandler(t, nil)

	Go(func() { panic("no handler") })

	msg := waitLog(t, logCh)
	if !strings.Contains(msg, "PANIC (goroutine): no handler") {
		t.Errorf("log = %q, want default handler output", msg)
	}
}

func TestSetPanicHandler_NilRestoresDefault(t *testing.T) {
	setHandler(t, func(any, []byte) {})
	SetPanicHandler(nil)
	if handler != nil {
		t.Error("SetPanicHandler(nil) did not clear the handler")
	}
}

// TestNoBareGoStatements fails if any production file outside this package
// starts a goroutine with a bare go statement instead of safego.Go.
func TestNoBareGoStatements(t *testing.T) {
	root := filepath.Join("..")
	fset := token.NewFileSet()
	var violations []string
	sawMain := false

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if path != root && (name == "testdata" || name == "vendor" || strings.HasPrefix(name, ".")) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if filepath.Clean(filepath.Dir(rel)) == "safego" {
			return nil
		}
		if rel == "main.go" {
			sawMain = true
		}
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		ast.Inspect(f, func(n ast.Node) bool {
			if g, ok := n.(*ast.GoStmt); ok {
				pos := fset.Position(g.Pos())
				violations = append(violations, fmt.Sprintf("%s:%d", rel, pos.Line))
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if !sawMain {
		t.Fatal("main.go was not parsed; walk root is wrong")
	}
	if len(violations) > 0 {
		t.Errorf("bare go statements found (use safego.Go):\n%s", strings.Join(violations, "\n"))
	}
}

type panicWriter struct{}

func (panicWriter) Write([]byte) (int, error) { panic("log sink failed") }

// TestDispatch_FallbackPanicIsContained covers the case where the installed
// handler panics and the default handler's logging panics too (the log sink
// itself is broken): dispatch must still return instead of crashing.
func TestDispatch_FallbackPanicIsContained(t *testing.T) {
	prev := handler
	t.Cleanup(func() { handler = prev })
	SetPanicHandler(func(any, []byte) { panic("handler failed") })

	prevOut := log.Writer()
	log.SetOutput(panicWriter{})
	t.Cleanup(func() { log.SetOutput(prevOut) })

	dispatch("boom", []byte("stack"))
}
