// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: Apache-2.0

// Command testsummary печатает число исполненных проверок из отчёта
// `go test -json`. «Отказов 0» без числа исполненного — не вердикт: отчёт без
// единой исполненной пробы, с пропуском или с пакетом, упавшим до проб,
// — отказ.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
)

type event struct {
	Action  string `json:"Action"`
	Package string `json:"Package"`
	Test    string `json:"Test"`
}

// Summary — итог отчёта.
type Summary struct {
	Packages     int
	Passed       int
	Failed       int
	Skipped      int
	FailedTests  []string
	SkippedTests []string
	FailedPkgs   []string
}

// Summarize читает отчёт go test -json.
func Summarize(r io.Reader) (Summary, error) {
	var s Summary
	pkgs := map[string]bool{}
	failedPkgs := map[string]bool{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<20), 16<<20)
	for sc.Scan() {
		var e event
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			continue
		}
		if e.Package != "" {
			pkgs[e.Package] = true
		}
		switch {
		case e.Test == "" && e.Action == "fail":
			failedPkgs[e.Package] = true
		case e.Test != "" && e.Action == "pass":
			s.Passed++
		case e.Test != "" && e.Action == "fail":
			s.Failed++
			s.FailedTests = append(s.FailedTests, e.Package+" "+e.Test)
		case e.Test != "" && e.Action == "skip":
			s.Skipped++
			s.SkippedTests = append(s.SkippedTests, e.Package+" "+e.Test)
		}
	}
	if err := sc.Err(); err != nil {
		return s, err
	}
	s.Packages = len(pkgs)
	for p := range failedPkgs {
		s.FailedPkgs = append(s.FailedPkgs, p)
	}
	sort.Strings(s.FailedPkgs)
	return s, nil
}

// Verdict — nil только при исполненных пробах без отказов и пропусков.
func (s Summary) Verdict() error {
	switch {
	case s.Passed+s.Failed == 0:
		return fmt.Errorf("no test was executed (%d packages in the report)", s.Packages)
	case s.Failed > 0 || len(s.FailedPkgs) > 0:
		return fmt.Errorf("%d tests failed, %d packages failed: %v %v", s.Failed, len(s.FailedPkgs), s.FailedTests, s.FailedPkgs)
	case s.Skipped > 0:
		return fmt.Errorf("%d tests skipped: %v", s.Skipped, s.SkippedTests)
	}
	return nil
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: testsummary <go test -json report>")
		os.Exit(2)
	}
	f, err := os.Open(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "testsummary:", err)
		os.Exit(2)
	}
	defer func() { _ = f.Close() }()
	s, err := Summarize(f)
	if err != nil {
		fmt.Fprintln(os.Stderr, "testsummary:", err)
		os.Exit(2)
	}
	fmt.Printf("tests: packages=%d passed=%d failed=%d skipped=%d\n", s.Packages, s.Passed, s.Failed, s.Skipped)
	if err := s.Verdict(); err != nil {
		fmt.Fprintln(os.Stderr, "testsummary: NOT GREEN:", err)
		os.Exit(1)
	}
}
