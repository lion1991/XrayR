//go:build !race

package controller_test

// raceEnabled skips the tests that run into upstream data races; the race
// detector fails them every time.
const raceEnabled = false
