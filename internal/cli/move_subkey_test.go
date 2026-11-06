package cli

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewMoveSubkeyCmd(t *testing.T) {
	cmd := newMoveSubkeyCmd()
	assert.NotNil(t, cmd)
	assert.Equal(t, "move-subkey", cmd.Use)
	assert.Contains(t, cmd.Short, "Move")
	assert.Contains(t, cmd.Short, "subkey")
	assert.Contains(t, cmd.Short, "YubiKey")
}
