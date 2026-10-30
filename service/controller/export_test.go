package controller

import "github.com/XrayR-project/XrayR/api"

// NewTestSingBoxController builds a node that may reach the local servers
// tests dial.
func NewTestSingBoxController(apiClient api.API, config *Config) *SingBoxController {
	c := NewSingBoxController(apiClient, config, "Keeper", SingBoxLog{})
	c.allowPrivate = true
	return c
}

// BoxGeneration counts box builds, so tests can tell a user update in place
// from a rebuild.
func (c *SingBoxController) BoxGeneration() int {
	c.access.Lock()
	defer c.access.Unlock()
	return c.boxGeneration
}
