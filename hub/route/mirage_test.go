package route

import (
	"encoding/json"
	"github.com/metacubex/http/httptest"
	"strings"
	"testing"
)

func TestMirageControllerRejectsBrowserAndRemoteRequests(t *testing.T) {
	for _, test := range []struct{ remote, origin string }{{"192.0.2.1:1234", ""}, {"127.0.0.1:1234", "https://foreign.example"}} {
		r := httptest.NewRequest("GET", "/capabilities", nil)
		r.RemoteAddr = test.remote
		r.Header.Set("Origin", test.origin)
		w := httptest.NewRecorder()
		mirageRouter().ServeHTTP(w, r)
		if w.Code != 403 {
			t.Fatalf("got %d", w.Code)
		}
	}
}

func TestMirageNoNodeDoesNotAdvertiseOrDial(t *testing.T) {
	for _, tc := range []struct{ method, path, body string }{{"GET", "/capabilities", ""}, {"POST", "/probe", `{"protocolVersion":2,"id":"abcdefgh","offset":5,"records":2,"outboundRevision":"forged"}`}} {
		r := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
		r.RemoteAddr = "127.0.0.1:1234"
		w := httptest.NewRecorder()
		mirageRouter().ServeHTTP(w, r)
		var reply map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &reply); err != nil {
			t.Fatal(err)
		}
		if reply["ok"] == true {
			t.Fatal("no node was reported successful")
		}
		if tc.path == "/capabilities" && len(reply["shapes"].([]any)) != 0 {
			t.Fatal("fake capability")
		}
	}
}
