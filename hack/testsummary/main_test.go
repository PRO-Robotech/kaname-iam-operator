// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"
)

func TestVerdict(t *testing.T) {
	cases := []struct {
		name   string
		report string
		green  bool
	}{
		{"executed and passed", `{"Action":"run","Package":"p","Test":"T"}
{"Action":"pass","Package":"p","Test":"T"}
{"Action":"pass","Package":"p"}`, true},
		{"nothing executed", `{"Action":"output","Package":"p","Output":"no test files"}
{"Action":"skip","Package":"p"}`, false},
		{"empty report", ``, false},
		{"a failed test", `{"Action":"pass","Package":"p","Test":"A"}
{"Action":"fail","Package":"p","Test":"B"}`, false},
		{"package failed before its tests", `{"Action":"pass","Package":"p","Test":"A"}
{"Action":"fail","Package":"q"}`, false},
		{"a skipped test", `{"Action":"pass","Package":"p","Test":"A"}
{"Action":"skip","Package":"p","Test":"B"}`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, err := Summarize(strings.NewReader(tc.report))
			if err != nil {
				t.Fatal(err)
			}
			if got := s.Verdict() == nil; got != tc.green {
				t.Fatalf("green=%v, want %v (%+v)", got, tc.green, s)
			}
		})
	}
}
