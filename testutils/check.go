package testutils

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TextFileEquals(t *testing.T, p, val string) {
	d, err := os.ReadFile(p)
	require.NoError(t, err)
	assert.EqualValues(t, val, string(d))
}
