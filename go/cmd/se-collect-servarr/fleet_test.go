package main

import (
	"reflect"
	"strings"
	"testing"
)

func env(pairs map[string]string) func(string) string {
	return func(key string) string { return pairs[key] }
}

// The receipt grammar, one shape per row. Every one of these is a
// configuration somebody has actually written, and the two that look like
// mistakes are the two the collection exists to publish rather than swallow.
func TestTheFleetIsReadFromItsReceiptsExactly(t *testing.T) {
	for label, tc := range map[string]struct {
		vars  map[string]string
		want  []instance
		ready []string
	}{
		"a v3 app and a v1 app, in configuration order": {
			vars: map[string]string{
				"SE_SERVARR_INSTANCES": "radarr,prowlarr:v1",
				"SE_RADARR_URL":        "http://radarr.invalid:7878",
				"SE_RADARR_API_KEY":    "k1",
				"SE_PROWLARR_URL":      "http://prowlarr.invalid:9696",
				"SE_PROWLARR_API_KEY":  "k2",
			},
			want: []instance{
				{name: "radarr", api: "v3", url: "http://radarr.invalid:7878", key: "k1"},
				{name: "prowlarr", api: "v1", url: "http://prowlarr.invalid:9696", key: "k2"},
			},
			ready: []string{"radarr", "prowlarr"},
		},
		// The hyphen is normalised in the VARIABLE name and kept in the
		// instance name, because the instance name is what every row is
		// namespaced by and an operator wrote it with the hyphen.
		"a hyphenated name reads underscored variables": {
			vars: map[string]string{
				"SE_SERVARR_INSTANCES":     "readarr-audio:v1",
				"SE_READARR_AUDIO_URL":     "http://readarr.invalid/",
				"SE_READARR_AUDIO_API_KEY": "k3",
			},
			want: []instance{
				// The trailing slash goes: the adapter builds
				// <url>/api/<family><path> and a doubled slash is a different
				// request to some reverse proxies.
				{name: "readarr-audio", api: "v1", url: "http://readarr.invalid", key: "k3"},
			},
			ready: []string{"readarr-audio"},
		},
		"a named instance with no receipts is a row, not a silent skip": {
			vars: map[string]string{"SE_SERVARR_INSTANCES": "sonarr"},
			want: []instance{{
				name: "sonarr", api: "v3",
				missing: []string{"SE_SONARR_URL", "SE_SONARR_API_KEY"},
			}},
		},
		"a duplicated name keeps its first entry and says so": {
			vars: map[string]string{
				"SE_SERVARR_INSTANCES": "lidarr:v1, lidarr:v3 ,lidarr",
				"SE_LIDARR_URL":        "http://lidarr.invalid",
				"SE_LIDARR_API_KEY":    "k4",
			},
			want: []instance{{
				name: "lidarr", api: "v1",
				url: "http://lidarr.invalid", key: "k4",
				duplicates: []string{"lidarr:v3", "lidarr"},
			}},
			ready: []string{"lidarr"},
		},
		// The paperless posture: a key that cannot survive a header is a
		// config fault named WITHOUT its value.
		"a key that cannot ride a header is a stated fault": {
			vars: map[string]string{
				"SE_SERVARR_INSTANCES": "sonarr",
				"SE_SONARR_URL":        "http://sonarr.invalid",
				"SE_SONARR_API_KEY":    "ke\ny",
			},
			want: []instance{{
				name: "sonarr", api: "v3", url: "http://sonarr.invalid", key: "ke\ny",
				missing: []string{"SE_SONARR_API_KEY (contains control or non-ASCII characters)"},
			}},
		},
		// Ids namespace by instance name WITH '/', so a slash-bearing name
		// cannot mint unambiguous ids at all.
		"a name that cannot mint an id is a stated fault": {
			vars: map[string]string{
				"SE_SERVARR_INSTANCES": "a/b",
				"SE_A/B_URL":           "http://ab.invalid",
				"SE_A/B_API_KEY":       "k5",
			},
			want: []instance{{
				name: "a/b", api: "v3", url: "http://ab.invalid", key: "k5",
				missing: []string{"instance name 'a/b' contains '/'"},
			}},
		},
		"an unset receipt list is a fleet of nothing": {
			vars: map[string]string{},
			want: nil,
		},
		"blank entries are skipped, not published as an instance named nothing": {
			vars: map[string]string{"SE_SERVARR_INSTANCES": " , ,"},
			want: nil,
		},
	} {
		got := instanceSpecs(env(tc.vars))
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s:\n got %+v\nwant %+v", label, got, tc.want)
			continue
		}
		var ready []string
		for _, app := range got {
			if app.ready() {
				ready = append(ready, app.name)
			}
		}
		if !reflect.DeepEqual(ready, tc.ready) {
			t.Errorf("%s: ready %v, want %v", label, ready, tc.ready)
		}
	}
}

// The key is the one value in this collector that must never travel, and the
// receipt is the only thing that holds it. Held here rather than trusted,
// because every other channel is checked by the harness and this one is
// checked by nothing: a fault named with its value would put the key in a
// ConfigMissing fact, on a row, on the wire.
func TestAFaultNamesTheVariableAndNeverItsValue(t *testing.T) {
	const secret = "ed9f89\u0000notakey"
	apps := instanceSpecs(env(map[string]string{
		"SE_SERVARR_INSTANCES": "radarr",
		"SE_RADARR_URL":        "http://radarr.invalid",
		"SE_RADARR_API_KEY":    secret,
	}))
	for _, fault := range apps[0].missing {
		if strings.Contains(fault, secret) {
			t.Fatalf("a stated fault carries the key itself: %q", fault)
		}
	}
	if len(apps[0].missing) != 1 {
		t.Fatalf("an unusable key is exactly one stated fault; got %v", apps[0].missing)
	}
}

// The stem the replay seam addresses a fleet document by, which is the
// capture's file name and the shim's slug() of the same request. A drift here
// is a directory of files nothing reads.
func TestThePayloadStemIsTheRequestThePathAnswers(t *testing.T) {
	for _, tc := range []struct {
		app  instance
		path string
		want string
	}{
		{instance{name: "radarr", api: "v3"}, pathStatus, "radarr-api-v3-system-status"},
		{instance{name: "radarr", api: "v3"}, pathQueueStatus, "radarr-api-v3-queue-status"},
		{instance{name: "prowlarr", api: "v1"}, pathQueue, "prowlarr-api-v1-queue"},
		{instance{name: "readarr-audio", api: "v1"}, pathHistory, "readarr-audio-api-v1-history"},
	} {
		if got := payloadStem(tc.app, tc.path); got != tc.want {
			t.Errorf("payloadStem(%s, %s) = %q, want %q", tc.app.name, tc.path, got, tc.want)
		}
	}
}
