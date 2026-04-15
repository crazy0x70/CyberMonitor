package server

import "testing"

func TestNormalizeAdminPathRejectsReservedPrefixes(t *testing.T) {
	t.Parallel()

	cases := []string{
		"/api",
		"/assets",
		"/ws",
	}

	for _, input := range cases {
		input := input
		t.Run(input, func(t *testing.T) {
			t.Parallel()

			if _, err := normalizeAdminPath(input); err == nil {
				t.Fatalf("expected reserved prefix %q to be rejected", input)
			}
		})
	}
}

func TestNormalizeAdminPathNormalizesValidPath(t *testing.T) {
	t.Parallel()

	got, err := normalizeAdminPath("cm-admin/")
	if err != nil {
		t.Fatalf("normalize valid path: %v", err)
	}
	if got != "/cm-admin" {
		t.Fatalf("expected normalized path /cm-admin, got %q", got)
	}
}
