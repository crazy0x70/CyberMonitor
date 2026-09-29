package updater

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

type redirectRoundTripper func(*http.Request) (*http.Response, error)

func (f redirectRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestUpdaterRedirectDestinations(t *testing.T) {
	for _, tc := range []struct {
		name, target string
		allowed      bool
	}{
		{"github", "https://github.com/asset", true},
		{"cdn signed query", "https://release-assets.githubusercontent.com/asset?sig=a%2Bb&expires=123", true},
		{"uppercase CDN", "https://RELEASE-ASSETS.GITHUBUSERCONTENT.COM/asset", true},
		{"explicit HTTPS port", "https://objects.githubusercontent.com:443/asset", true},
		{"HTTP downgrade", "http://github.com/asset", false},
		{"CDN HTTP downgrade", "http://objects.githubusercontent.com/asset", false},
		{"non HTTPS port", "https://github.com:8443/asset", false},
		{"CDN non HTTPS port", "https://objects.githubusercontent.com:80/asset", false},
		{"userinfo", "https://user:secret@github.com/asset", false},
		{"empty userinfo", "https://@github.com/asset", false},
		{"CDN userinfo", "https://user@objects.githubusercontent.com/asset", false},
		{"fake suffix", "https://evilgithubusercontent.com/asset", false},
		{"suffix extension", "https://objects.githubusercontent.com.evil.example/asset", false},
		{"third party", "https://example.com/asset", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := NewClient("", KindServer, "").HTTPClient
			var visited []string
			client.Transport = redirectRoundTripper(func(req *http.Request) (*http.Response, error) {
				visited = append(visited, req.URL.String())
				status, headers := http.StatusOK, make(http.Header)
				if len(visited) == 1 {
					status = http.StatusFound
					headers.Set("Location", tc.target)
				}
				return &http.Response{StatusCode: status, Header: headers, Body: io.NopCloser(strings.NewReader("")), Request: req}, nil
			})
			resp, err := client.Get("https://github.com/start")
			if resp != nil {
				resp.Body.Close()
			}
			if tc.allowed {
				if err != nil {
					t.Fatalf("valid redirect rejected: %v", err)
				}
				if len(visited) != 2 || visited[1] != tc.target {
					t.Fatalf("redirect URL changed: %v", visited)
				}
			} else {
				if err == nil {
					t.Fatal("untrusted redirect accepted")
				}
				if len(visited) != 1 {
					t.Fatalf("untrusted destination contacted: %v", visited)
				}
			}
		})
	}
}

func TestUpdaterRedirectLimit(t *testing.T) {
	for _, redirects := range []int{9, 10, 20} {
		t.Run(fmt.Sprint(redirects), func(t *testing.T) {
			client := NewClient("", KindServer, "").HTTPClient
			calls := 0
			client.Transport = redirectRoundTripper(func(req *http.Request) (*http.Response, error) {
				calls++
				status, headers := http.StatusOK, make(http.Header)
				if calls <= redirects {
					status = http.StatusFound
					headers.Set("Location", "https://github.com/loop")
				}
				return &http.Response{StatusCode: status, Header: headers, Body: io.NopCloser(strings.NewReader("")), Request: req}, nil
			})
			resp, err := client.Get("https://github.com/loop")
			if resp != nil {
				resp.Body.Close()
			}
			if redirects < 10 {
				if err != nil || calls != 10 {
					t.Fatalf("nine redirects: calls=%d err=%v", calls, err)
				}
			} else if err == nil || calls != 10 {
				t.Fatalf("redirect cap: calls=%d err=%v", calls, err)
			}
		})
	}
}

func TestReleaseAssetURLRejectsUserinfo(t *testing.T) {
	client := NewClient("", KindServer, "")
	for _, userinfo := range []string{"", "user@", "user:secret@", "@"} {
		t.Run(userinfo, func(t *testing.T) {
			raw := "https://" + userinfo + "github.com/" + DefaultRepo + "/releases/download/v1.2.3/" + checksumAssetName
			_, err := client.parseGitHubReleaseAssetURL(raw, checksumAssetName)
			if (err == nil) != (userinfo == "") {
				t.Fatalf("userinfo %q: err=%v", userinfo, err)
			}
		})
	}
}
