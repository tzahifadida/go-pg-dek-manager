package gopgdekmanager

import (
	"context"
	"database/sql"
	"fmt"
	"github.com/docker/go-connections/nat"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	// Import the pgx v5 driver
	_ "github.com/jackc/pgx/v5/stdlib"
)

const (
	testDBName     = "testdb"
	testDBUser     = "testuser"
	testDBPassword = "testpass"
)

func setupTestDatabase(t *testing.T) (*sql.DB, func()) {
	ctx := context.Background()

	// Create PostgreSQL container
	pgContainer, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        "postgres:13",
			ExposedPorts: []string{"5432/tcp"},
			Env: map[string]string{
				"POSTGRES_DB":       testDBName,
				"POSTGRES_USER":     testDBUser,
				"POSTGRES_PASSWORD": testDBPassword,
			},
			WaitingFor: wait.ForAll(
				wait.ForLog("database system is ready to accept connections"),
				wait.ForSQL("5432/tcp", "pgx", func(host string, port nat.Port) string {
					return fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
						host, port.Port(), testDBUser, testDBPassword, testDBName)
				}),
			).WithDeadline(1 * time.Minute),
		},
		Started: true,
	})
	require.NoError(t, err)

	// Get host and port
	host, err := pgContainer.Host(ctx)
	require.NoError(t, err)
	port, err := pgContainer.MappedPort(ctx, "5432")
	require.NoError(t, err)

	// Connect to the database
	dsn := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable",
		host, port.Int(), testDBUser, testDBPassword, testDBName)
	db, err := sql.Open("pgx", dsn)
	require.NoError(t, err)

	// Ensure the database is ready
	err = waitForDB(db)
	require.NoError(t, err)

	// Return cleanup function
	cleanup := func() {
		db.Close()
		pgContainer.Terminate(ctx)
	}

	return db, cleanup
}

func waitForDB(db *sql.DB) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("timeout waiting for database to be ready")
		default:
			err := db.PingContext(ctx)
			if err == nil {
				return nil
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
}
func TestDEKManager(t *testing.T) {
	db, cleanup := setupTestDatabase(t)
	defer cleanup()

	// Test MEK
	mek := []byte("01234567890123456789012345678901") // 32 bytes

	t.Run("NewDEKManager", func(t *testing.T) {
		manager, err := NewDEKManager(db, mek,
			WithSchemaName("test_schema"),
			WithTablePrefix("test_prefix"),
			WithCleanupPeriod(24*time.Hour),
			WithDEKRotationPeriod(12*time.Hour),
		)
		require.NoError(t, err)
		assert.NotNil(t, manager)
		defer manager.Shutdown()

		assert.Equal(t, "test_schema", manager.SchemaName())
		assert.Equal(t, "test_prefix", manager.TablePrefix())
	})

	t.Run("GetDEK", func(t *testing.T) {
		manager, err := NewDEKManager(db, mek)
		require.NoError(t, err)
		defer manager.Shutdown()

		// Get a new DEK
		dek1, version1, err := manager.GetDEK("test_key")
		require.NoError(t, err)
		assert.NotNil(t, dek1)
		assert.Equal(t, 1, version1)

		// Get the same DEK again
		dek2, version2, err := manager.GetDEK("test_key")
		require.NoError(t, err)
		assert.Equal(t, dek1, dek2)
		assert.Equal(t, version1, version2)

		// Get a different DEK
		dek3, version3, err := manager.GetDEK("another_key")
		require.NoError(t, err)
		assert.NotEqual(t, dek1, dek3)
		assert.Equal(t, 1, version3)
	})

	t.Run("RotateDEK", func(t *testing.T) {
		manager, err := NewDEKManager(db, mek)
		require.NoError(t, err)
		defer manager.Shutdown()

		// Get initial DEK
		dek1, version1, err := manager.GetDEK("rotate_key")
		require.NoError(t, err)

		// Rotate DEK
		err = manager.RotateDEK("rotate_key")
		require.NoError(t, err)

		// Get rotated DEK
		dek2, version2, err := manager.GetDEK("rotate_key")
		require.NoError(t, err)
		assert.NotEqual(t, dek1, dek2)
		assert.Equal(t, version1+1, version2)
	})

	t.Run("MEKTransition", func(t *testing.T) {
		db, cleanup := setupTestDatabase(t)
		defer cleanup()

		oldMEK := []byte("01234567890123456789012345678901") // 32 byte MEK
		newMEK := []byte("12345678901234567890123456789012") // New 32 byte MEK

		// Create manager with old MEK
		oldManager, err := NewDEKManager(db, oldMEK)
		require.NoError(t, err)

		// Create some DEKs
		dek1, version1, err := oldManager.GetDEK("transition_key1")
		require.NoError(t, err)
		dek2, version2, err := oldManager.GetDEK("transition_key2")
		require.NoError(t, err)

		oldManager.Shutdown()

		// Create new manager with new MEK and old MEK
		newManager, err := NewDEKManager(db, newMEK, WithOldMEK(oldMEK))
		require.NoError(t, err)
		defer newManager.Shutdown()

		// Check if DEKs are still accessible and have been re-encrypted
		newDek1, newVersion1, err := newManager.GetDEK("transition_key1")
		require.NoError(t, err)
		assert.Equal(t, version1, newVersion1)
		assert.Equal(t, dek1, newDek1) // The DEK content should be the same

		newDek2, newVersion2, err := newManager.GetDEK("transition_key2")
		require.NoError(t, err)
		assert.Equal(t, version2, newVersion2)
		assert.Equal(t, dek2, newDek2) // The DEK content should be the same

		// Try to create a new DEK with the new manager
		newDek3, newVersion3, err := newManager.GetDEK("transition_key3")
		require.NoError(t, err)
		assert.NotNil(t, newDek3)
		assert.Equal(t, 1, newVersion3)

		// Verify that we can create a new manager with just the old MEK
		oldMEKManager, err := NewDEKManager(db, oldMEK)
		require.NoError(t, err)
		defer oldMEKManager.Shutdown()

		// Verify we can still access existing DEKs with the old MEK
		oldDek1, oldVersion1, err := oldMEKManager.GetDEK("transition_key1")
		require.NoError(t, err)
		assert.Equal(t, dek1, oldDek1)
		assert.Equal(t, version1, oldVersion1)

		// Verify we cannot rotate DEKs with the old MEK
		err = oldMEKManager.RotateDEK("transition_key1")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "cannot rotate DEK with an old version of MEK")

		// Verify we cannot create new DEKs with the old MEK
		_, _, err = oldMEKManager.GetDEK("new_key_with_old_mek")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "cannot create new DEK with old MEK")
	})

	t.Run("RemoveDEKs", func(t *testing.T) {
		manager, err := NewDEKManager(db, mek)
		require.NoError(t, err)
		defer manager.Shutdown()

		// Create multiple versions of a DEK
		_, _, err = manager.GetDEK("remove_key")
		require.NoError(t, err)
		err = manager.RotateDEK("remove_key")
		require.NoError(t, err)
		err = manager.RotateDEK("remove_key")
		require.NoError(t, err)

		// Remove DEKs up to version 2
		err = manager.RemoveDEKs("remove_key", 2)
		require.NoError(t, err)

		// Check if only the latest version remains
		dek, version, err := manager.GetDEK("remove_key")
		require.NoError(t, err)
		assert.NotNil(t, dek)
		assert.Equal(t, 3, version)
	})

	t.Run("Caching", func(t *testing.T) {
		manager, err := NewDEKManager(db, mek, WithCacheExpiration(50*time.Millisecond))
		require.NoError(t, err)
		defer manager.Shutdown()

		// Get a DEK
		dek1, _, err := manager.GetDEK("cache_key")
		require.NoError(t, err)

		// Get the same DEK again (should be from cache)
		dek2, _, err := manager.GetDEK("cache_key")
		require.NoError(t, err)
		assert.Equal(t, dek1, dek2)

		// Wait for cache to expire
		time.Sleep(100 * time.Millisecond)

		// Get the DEK again (should fetch from DB)
		dek3, _, err := manager.GetDEK("cache_key")
		require.NoError(t, err)
		assert.Equal(t, dek1, dek3) // The DEK should be the same, but it was fetched from DB
	})

	t.Run("Concurrent operations", func(t *testing.T) {
		manager, err := NewDEKManager(db, mek)
		require.NoError(t, err)
		defer manager.Shutdown()

		// Perform concurrent DEK retrievals and rotations
		concurrency := 10
		ch := make(chan bool, concurrency)

		for i := 0; i < concurrency; i++ {
			go func(id int) {
				keyName := fmt.Sprintf("concurrent_key_%d", id)
				_, _, err := manager.GetDEK(keyName)
				assert.NoError(t, err)

				err = manager.RotateDEK(keyName)
				assert.NoError(t, err)

				ch <- true
			}(i)
		}

		// Wait for all goroutines to finish
		for i := 0; i < concurrency; i++ {
			<-ch
		}
	})
}

func TestInvalidMEKSize(t *testing.T) {
	db, cleanup := setupTestDatabase(t)
	defer cleanup()

	invalidMEK := []byte("too_short") // Not 32 bytes

	_, err := NewDEKManager(db, invalidMEK)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid MEK size")
}

func TestCleanupOldDEKs(t *testing.T) {
	db, cleanup := setupTestDatabase(t)
	defer cleanup()

	mek := []byte("01234567890123456789012345678901") // 32 bytes
	shortCleanupPeriod := 1 * time.Second

	manager, err := NewDEKManager(db, mek, WithCleanupPeriod(shortCleanupPeriod))
	require.NoError(t, err)
	defer manager.Shutdown()

	// Create some DEKs
	_, _, err = manager.GetDEK("cleanup_key1")
	require.NoError(t, err)
	_, _, err = manager.GetDEK("cleanup_key2")
	require.NoError(t, err)

	// Wait for cleanup to occur
	time.Sleep(2 * time.Second)

	// Try to get the DEKs again (should create new ones)
	dek1, version1, err := manager.GetDEK("cleanup_key1")
	require.NoError(t, err)
	assert.NotNil(t, dek1)
	assert.Equal(t, 1, version1)

	dek2, version2, err := manager.GetDEK("cleanup_key2")
	require.NoError(t, err)
	assert.NotNil(t, dek2)
	assert.Equal(t, 1, version2)
}

// Add more tests as needed...
