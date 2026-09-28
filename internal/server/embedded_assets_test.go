package server

import "testing"

func TestVerifyEmbeddedWebAssets(t *testing.T) {
	if err := verifyEmbeddedWebAssets(); err != nil {
		t.Fatalf("verifyEmbeddedWebAssets() = %v, want nil", err)
	}
}

func TestEmbeddedWebAssetsReadable(t *testing.T) {
	for _, name := range []string{
		"web/public/index.html",
		"web/public/assets/monitor.js",
		"web/public/assets/styles.css",
		"web/public/assets/theme.js",
		"web/dist/admin/index.html",
	} {
		data, err := webFS.ReadFile(name)
		if err != nil {
			t.Errorf("webFS.ReadFile(%q) 失败: %v", name, err)
			continue
		}
		if len(data) == 0 {
			t.Errorf("webFS.ReadFile(%q) 返回空内容", name)
		}
	}
}
