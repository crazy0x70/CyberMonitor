package server

import "testing"

func TestAdminDocumentTitleUsesSiteTitle(t *testing.T) {
	t.Parallel()

	if got := adminDocumentTitle(""); got != "CyberMonitor 管理后台" {
		t.Fatalf("expected default admin title, got %q", got)
	}
	if got := adminDocumentTitle("极夜监控台"); got != "极夜监控台 管理后台" {
		t.Fatalf("expected site title based admin title, got %q", got)
	}
}
