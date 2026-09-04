package cmd

import (
	"testing"
	"time"
)

func TestParseExpiry(t *testing.T) {
	tests := []struct {
		value     string
		want      time.Duration
		wantError bool
	}{
		{value: "365", want: 365 * 24 * time.Hour},
		{value: "1y", want: 365 * 24 * time.Hour},
		{value: "2y", want: 730 * 24 * time.Hour},
		{value: "0", wantError: true},
		{value: "-1", wantError: true},
		{value: "1d", wantError: true},
		{value: "", wantError: true},
	}

	for _, test := range tests {
		t.Run(test.value, func(t *testing.T) {
			got, err := parseExpiry(test.value)
			if test.wantError {
				if err == nil {
					t.Fatal("parseExpiry() error = nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("parseExpiry() error = %v", err)
			}
			if got != test.want {
				t.Errorf("parseExpiry() = %s, want %s", got, test.want)
			}
		})
	}
}
