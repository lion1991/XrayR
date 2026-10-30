package controller

// BoxGeneration counts box builds, so tests can tell a user update in place
// from a rebuild.
func (c *SingBoxController) BoxGeneration() int {
	c.access.Lock()
	defer c.access.Unlock()
	return c.boxGeneration
}
