package s3proxy

import "os"

func writeFile(p, v string) error { return os.WriteFile(p, []byte(v), 0o600) }
