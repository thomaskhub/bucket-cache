package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfigCheck(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good.yaml")
	bad := filepath.Join(dir, "bad.yaml")
	os.WriteFile(good, []byte("storage:\n  db_path: "+filepath.Join(dir, "p.db")+"\n"), 0o600)
	os.WriteFile(bad, []byte("log:\n  level: loud\n"), 0o600)

	var out, errb bytes.Buffer
	if code := run([]string{"config", "check", "--config", good}, &out, &errb); code != 0 {
		t.Fatalf("good config: exit %d, %s", code, errb.String())
	}
	errb.Reset()
	if code := run([]string{"config", "check", "--config", bad}, &out, &errb); code != 1 || !strings.Contains(errb.String(), "log.level") {
		t.Fatalf("bad config: exit %d, %s", code, errb.String())
	}
}

func TestUsage(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run(nil, &out, &errb); code != 2 || !strings.Contains(errb.String(), "Usage") {
		t.Fatalf("no args: exit %d", code)
	}
	if code := run([]string{"version"}, &out, &errb); code != 0 || !strings.Contains(out.String(), "yproxy") {
		t.Fatalf("version: exit %d", code)
	}
}
