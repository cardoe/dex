package main

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewLogger(t *testing.T) {
	t.Run("JSON", func(t *testing.T) {
		logger, err := newLogger(slog.LevelInfo, "json")
		require.NoError(t, err)
		require.NotEqual(t, (*slog.Logger)(nil), logger)
	})

	t.Run("Text", func(t *testing.T) {
		logger, err := newLogger(slog.LevelError, "text")
		require.NoError(t, err)
		require.NotEqual(t, (*slog.Logger)(nil), logger)
	})

	t.Run("Unknown", func(t *testing.T) {
		logger, err := newLogger(slog.LevelError, "gofmt")
		require.Error(t, err)
		require.Equal(t, "log format is not one of the supported values (json, text): gofmt", err.Error())
		require.Equal(t, (*slog.Logger)(nil), logger)
	})
}

func TestLoadClientsFromDir(t *testing.T) {
	logger, err := newLogger(slog.LevelInfo, "text")
	require.NoError(t, err)

	t.Run("EmptyDir", func(t *testing.T) {
		clients, err := loadClientsFromDir("", logger)
		require.NoError(t, err)
		require.Nil(t, clients)
	})

	t.Run("NonExistentDir", func(t *testing.T) {
		clients, err := loadClientsFromDir("/nonexistent/path", logger)
		require.NoError(t, err)
		require.Nil(t, clients)
	})

	t.Run("ValidClientsDir", func(t *testing.T) {
		// Create temporary directory
		tmpDir := t.TempDir()

		// Create test client files
		client1 := `name: "Test Client 1"
redirectURIs:
  - "http://localhost:8080/callback"
secret: "test-secret-1"`

		client2 := `name: "Test Client 2"
redirectURIs:
  - "http://localhost:9090/callback"
public: true`

		err := os.WriteFile(filepath.Join(tmpDir, "client1.yaml"), []byte(client1), 0644)
		require.NoError(t, err)

		err = os.WriteFile(filepath.Join(tmpDir, "client2.yml"), []byte(client2), 0644)
		require.NoError(t, err)

		// Create a non-yaml file that should be ignored
		err = os.WriteFile(filepath.Join(tmpDir, "README.txt"), []byte("ignore me"), 0644)
		require.NoError(t, err)

		// Load clients
		clients, err := loadClientsFromDir(tmpDir, logger)
		require.NoError(t, err)
		require.Len(t, clients, 2)

		// Verify client1
		require.Equal(t, "client1", clients[0].ID)
		require.Equal(t, "Test Client 1", clients[0].Name)
		require.Equal(t, []string{"http://localhost:8080/callback"}, clients[0].RedirectURIs)
		require.Equal(t, "test-secret-1", clients[0].Secret)

		// Verify client2
		require.Equal(t, "client2", clients[1].ID)
		require.Equal(t, "Test Client 2", clients[1].Name)
		require.Equal(t, []string{"http://localhost:9090/callback"}, clients[1].RedirectURIs)
		require.True(t, clients[1].Public)
	})

	t.Run("ClientIDMismatch", func(t *testing.T) {
		tmpDir := t.TempDir()

		// Create client with mismatched ID
		clientWithID := `id: "different-id"
name: "Test Client"
redirectURIs:
  - "http://localhost:8080/callback"
secret: "test-secret"`

		err := os.WriteFile(filepath.Join(tmpDir, "client1.yaml"), []byte(clientWithID), 0644)
		require.NoError(t, err)

		// This should fail because the ID in the file doesn't match the filename
		clients, err := loadClientsFromDir(tmpDir, logger)
		require.Error(t, err)
		require.Contains(t, err.Error(), "client ID mismatch")
		require.Nil(t, clients)
	})

	t.Run("InvalidYAML", func(t *testing.T) {
		tmpDir := t.TempDir()

		// Create invalid YAML file
		err := os.WriteFile(filepath.Join(tmpDir, "invalid.yaml"), []byte("invalid: [yaml"), 0644)
		require.NoError(t, err)

		clients, err := loadClientsFromDir(tmpDir, logger)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to parse")
		require.Nil(t, clients)
	})

	t.Run("NotADirectory", func(t *testing.T) {
		tmpFile := filepath.Join(t.TempDir(), "notadir")
		err := os.WriteFile(tmpFile, []byte("test"), 0644)
		require.NoError(t, err)

		clients, err := loadClientsFromDir(tmpFile, logger)
		require.Error(t, err)
		require.Contains(t, err.Error(), "not a directory")
		require.Nil(t, clients)
	})
}
