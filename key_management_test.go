package gopgdekmanager

import (
	"context"
	"crypto/rand"
	"database/sql"
	"fmt"
	"github.com/docker/go-connections/nat"
	"io"
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

	t.Run("RegisterKeyAndGetDEK", func(t *testing.T) {
		manager, err := NewDEKManager(db, mek)
		require.NoError(t, err)
		defer manager.Shutdown()

		// Register a new key
		err = manager.RegisterKey(context.Background(), "test_key")
		require.NoError(t, err)

		// Get a DEK for the registered key
		dek1, version1, err := manager.GetDEK(context.Background(), "test_key")
		require.NoError(t, err)
		assert.NotNil(t, dek1)
		assert.Equal(t, 1, version1)

		// Get the same DEK again
		dek2, version2, err := manager.GetDEK(context.Background(), "test_key")
		require.NoError(t, err)
		assert.Equal(t, dek1, dek2)
		assert.Equal(t, version1, version2)

		// Register a different key
		err = manager.RegisterKey(context.Background(), "another_key")
		require.NoError(t, err)

		// Get a DEK for the new key
		dek3, version3, err := manager.GetDEK(context.Background(), "another_key")
		require.NoError(t, err)
		assert.NotEqual(t, dek1, dek3)
		assert.Equal(t, 1, version3)
	})

	t.Run("RotateDEK", func(t *testing.T) {
		manager, err := NewDEKManager(db, mek)
		require.NoError(t, err)
		defer manager.Shutdown()

		// Register a key
		err = manager.RegisterKey(context.Background(), "rotate_key")
		require.NoError(t, err)

		// Get initial DEK
		dek1, version1, err := manager.GetDEK(context.Background(), "rotate_key")
		require.NoError(t, err)

		// Rotate DEK
		err = manager.RotateDEK(context.Background(), "rotate_key")
		require.NoError(t, err)

		// Get rotated DEK
		dek2, version2, err := manager.GetDEK(context.Background(), "rotate_key")
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

		ctx := context.Background()

		// Register keys
		err = oldManager.RegisterKey(ctx, "transition_key1")
		require.NoError(t, err)
		err = oldManager.RegisterKey(ctx, "transition_key2")
		require.NoError(t, err)

		// Create DEKs
		dek1, version1, err := oldManager.GetDEK(ctx, "transition_key1")
		require.NoError(t, err)
		dek2, version2, err := oldManager.GetDEK(ctx, "transition_key2")
		require.NoError(t, err)

		oldManager.Shutdown()

		// Create new manager with new MEK and old MEK
		newManager, err := NewDEKManager(db, newMEK, WithOldMEK(oldMEK))
		require.NoError(t, err)
		defer newManager.Shutdown()

		// Check if DEKs are still accessible and have been re-encrypted
		newDek1, newVersion1, err := newManager.GetDEK(ctx, "transition_key1")
		require.NoError(t, err)
		assert.Equal(t, version1, newVersion1)
		assert.Equal(t, dek1, newDek1) // The DEK content should be the same

		newDek2, newVersion2, err := newManager.GetDEK(ctx, "transition_key2")
		require.NoError(t, err)
		assert.Equal(t, version2, newVersion2)
		assert.Equal(t, dek2, newDek2) // The DEK content should be the same

		// Register a new key with the new manager
		err = newManager.RegisterKey(ctx, "transition_key3")
		require.NoError(t, err)

		// Get DEK for the new key
		newDek3, newVersion3, err := newManager.GetDEK(ctx, "transition_key3")
		require.NoError(t, err)
		assert.NotNil(t, newDek3)
		assert.Equal(t, 1, newVersion3)

		// Verify that we can create a new manager with just the old MEK
		oldMEKManager, err := NewDEKManager(db, oldMEK)
		require.NoError(t, err)
		defer oldMEKManager.Shutdown()

		// Verify we can still access existing DEKs with the old MEK
		oldDek1, oldVersion1, err := oldMEKManager.GetDEK(ctx, "transition_key1")
		require.NoError(t, err)
		assert.Equal(t, dek1, oldDek1)
		assert.Equal(t, version1, oldVersion1)

		// Verify we cannot rotate DEKs with the old MEK
		err = oldMEKManager.RotateDEK(ctx, "transition_key1")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "cannot rotate DEK with an old version of MEK")

		// Verify we can register a new key with the old MEK manager
		err = oldMEKManager.RegisterKey(ctx, "new_key_with_old_mek")
		assert.NoError(t, err) // This should succeed as registration is independent of MEK

		// But we should not be able to create a new DEK with the old MEK
		_, _, err = oldMEKManager.GetDEK(ctx, "new_key_with_old_mek")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "cannot create new DEK with old MEK")
	})

	t.Run("RemoveKey", func(t *testing.T) {
		manager, err := NewDEKManager(db, mek)
		require.NoError(t, err)
		defer manager.Shutdown()

		// Register a key
		err = manager.RegisterKey(context.Background(), "remove_key")
		require.NoError(t, err)

		// Create multiple versions of a DEK
		_, _, err = manager.GetDEK(context.Background(), "remove_key")
		require.NoError(t, err)
		err = manager.RotateDEK(context.Background(), "remove_key")
		require.NoError(t, err)
		err = manager.RotateDEK(context.Background(), "remove_key")
		require.NoError(t, err)

		// Remove the key
		err = manager.RemoveKey(context.Background(), "remove_key")
		require.NoError(t, err)

		// Check if the key is removed
		_, _, err = manager.GetDEK(context.Background(), "remove_key")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "key 'remove_key' not registered")
	})

	t.Run("Caching", func(t *testing.T) {
		manager, err := NewDEKManager(db, mek, WithCacheExpiration(50*time.Millisecond))
		require.NoError(t, err)
		defer manager.Shutdown()

		// Register a key
		err = manager.RegisterKey(context.Background(), "cache_key")
		require.NoError(t, err)

		// Get a DEK
		dek1, _, err := manager.GetDEK(context.Background(), "cache_key")
		require.NoError(t, err)

		// Get the same DEK again (should be from cache)
		dek2, _, err := manager.GetDEK(context.Background(), "cache_key")
		require.NoError(t, err)
		assert.Equal(t, dek1, dek2)

		// Wait for cache to expire
		time.Sleep(100 * time.Millisecond)

		// Get the DEK again (should fetch from DB)
		dek3, _, err := manager.GetDEK(context.Background(), "cache_key")
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
				ctx := context.Background()
				keyName := fmt.Sprintf("concurrent_key_%d", id)
				err := manager.RegisterKey(ctx, keyName)
				assert.NoError(t, err)

				_, _, err = manager.GetDEK(ctx, keyName)
				assert.NoError(t, err)

				err = manager.RotateDEK(ctx, keyName)
				assert.NoError(t, err)

				ch <- true
			}(i)
		}

		// Wait for all goroutines to finish
		for i := 0; i < concurrency; i++ {
			<-ch
		}
	})

	t.Run("RegisterKeyAndGetDEK", func(t *testing.T) {
		manager, err := NewDEKManager(db, mek)
		require.NoError(t, err)
		defer manager.Shutdown()

		ctx := context.Background()

		// Register a new key
		err = manager.RegisterKey(ctx, "test_key")
		require.NoError(t, err)

		// Register the same key again (should be idempotent)
		err = manager.RegisterKey(ctx, "test_key")
		require.NoError(t, err)

		// Get a DEK for the registered key
		dek1, version1, err := manager.GetDEK(ctx, "test_key")
		require.NoError(t, err)
		assert.NotNil(t, dek1)
		assert.Equal(t, 1, version1)

		// Get the same DEK again
		dek2, version2, err := manager.GetDEK(ctx, "test_key")
		require.NoError(t, err)
		assert.Equal(t, dek1, dek2)
		assert.Equal(t, version1, version2)

		// Register a different key
		err = manager.RegisterKey(ctx, "another_key")
		require.NoError(t, err)

		// Get a DEK for the new key
		dek3, version3, err := manager.GetDEK(ctx, "another_key")
		require.NoError(t, err)
		assert.NotEqual(t, dek1, dek3)
		assert.Equal(t, 1, version3)
	})

	t.Run("RegisterKeyWithSkipCache", func(t *testing.T) {
		manager, err := NewDEKManager(db, mek)
		require.NoError(t, err)
		defer manager.Shutdown()

		ctx := context.Background()

		// Register a key
		err = manager.RegisterKey(ctx, "skip_cache_key")
		require.NoError(t, err)

		// Register the same key with skip cache option
		err = manager.RegisterKey(ctx, "skip_cache_key", WithSkipCache())
		require.NoError(t, err)

		// Get a DEK for the registered key
		dek, version, err := manager.GetDEK(ctx, "skip_cache_key")
		require.NoError(t, err)
		assert.NotNil(t, dek)
		assert.Equal(t, 1, version)
	})

	t.Run("KeyFunctionCaching", func(t *testing.T) {
		manager, err := NewDEKManager(db, mek)
		require.NoError(t, err)
		defer manager.Shutdown()

		ctx := context.Background()

		// Register a key
		err = manager.RegisterKey(ctx, "cache_test_key")
		require.NoError(t, err)

		// Get DEK to ensure the key-function is cached
		_, _, err = manager.GetDEK(ctx, "cache_test_key")
		require.NoError(t, err)

		// Attempt to register with a different function (should fail due to cache)
		err = manager.RegisterKeyWithFunction(ctx, "cache_test_key", "aes192-random")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "already registered with a different function")

		// Register a new key with skip cache option
		err = manager.RegisterKey(ctx, "new_cache_test_key", WithSkipCache())
		require.NoError(t, err)

		// Verify that the new key was registered successfully
		_, _, err = manager.GetDEK(ctx, "new_cache_test_key")
		require.NoError(t, err)

		// Attempt to register the new key again with a different function (should fail because it's in the database)
		err = manager.RegisterKeyWithFunction(ctx, "new_cache_test_key", "aes192-random")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "already registered with a different function")
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

	// Register and create some DEKs
	err = manager.RegisterKey(context.Background(), "cleanup_key1")
	require.NoError(t, err)
	err = manager.RegisterKey(context.Background(), "cleanup_key2")
	require.NoError(t, err)

	_, _, err = manager.GetDEK(context.Background(), "cleanup_key1")
	require.NoError(t, err)
	_, _, err = manager.GetDEK(context.Background(), "cleanup_key2")
	require.NoError(t, err)

	// Wait for cleanup to occur
	time.Sleep(2 * time.Second)

	// Try to get the DEKs again (should return the same DEKs)
	dek1, version1, err := manager.GetDEK(context.Background(), "cleanup_key1")
	require.NoError(t, err)
	assert.NotNil(t, dek1)
	assert.Equal(t, 1, version1)

	dek2, version2, err := manager.GetDEK(context.Background(), "cleanup_key2")
	require.NoError(t, err)
	assert.NotNil(t, dek2)
	assert.Equal(t, 1, version2)
}

func TestGetDEKByVersion(t *testing.T) {
	db, cleanup := setupTestDatabase(t)
	defer cleanup()

	mek := []byte("01234567890123456789012345678901") // 32 bytes

	manager, err := NewDEKManager(db, mek)
	require.NoError(t, err)
	defer manager.Shutdown()

	ctx := context.Background()

	// Register a key
	err = manager.RegisterKey(ctx, "version_test_key")
	require.NoError(t, err)

	// Create initial DEK
	dek1, version1, err := manager.GetDEK(ctx, "version_test_key")
	require.NoError(t, err)
	assert.Equal(t, 1, version1)

	// Rotate DEK
	err = manager.RotateDEK(ctx, "version_test_key")
	require.NoError(t, err)

	// Get rotated DEK
	dek2, version2, err := manager.GetDEK(ctx, "version_test_key")
	require.NoError(t, err)
	assert.Equal(t, 2, version2)

	// Test GetDEKByVersion for the latest version
	retrievedDEK2, err := manager.GetDEKByVersion(ctx, "version_test_key", 2)
	require.NoError(t, err)
	assert.Equal(t, dek2, retrievedDEK2)

	// Test GetDEKByVersion for the older version
	retrievedDEK1, err := manager.GetDEKByVersion(ctx, "version_test_key", 1)
	require.NoError(t, err)
	assert.Equal(t, dek1, retrievedDEK1)

	// Test non-existent version
	_, err = manager.GetDEKByVersion(ctx, "version_test_key", 3)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "DEK not found")

	// Test with a different key that doesn't exist
	_, err = manager.GetDEKByVersion(ctx, "non_existent_key", 1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "DEK not found")
}

func TestRegisterKeyWithFunction(t *testing.T) {
	db, cleanup := setupTestDatabase(t)
	defer cleanup()

	mek := []byte("01234567890123456789012345678901") // 32 bytes

	manager, err := NewDEKManager(db, mek)
	require.NoError(t, err)
	defer manager.Shutdown()

	ctx := context.Background()

	// Register a key with the default function
	err = manager.RegisterKey(ctx, "default_key")
	require.NoError(t, err)

	// Register a key with a specific function
	err = manager.RegisterKeyWithFunction(ctx, "aes192_key", "aes192-random")
	require.NoError(t, err)

	// Try to register the same key with a different function (should fail)
	err = manager.RegisterKeyWithFunction(ctx, "aes192_key", "aes256-random")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already registered with a different function")

	// Register a key with a non-existent function (should fail)
	err = manager.RegisterKeyWithFunction(ctx, "invalid_key", "non-existent-function")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not registered")

	// Get DEKs for the registered keys
	dek1, _, err := manager.GetDEK(ctx, "default_key")
	require.NoError(t, err)
	assert.Equal(t, 32, len(dek1)) // Default is AES-256

	dek2, _, err := manager.GetDEK(ctx, "aes192_key")
	require.NoError(t, err)
	assert.Equal(t, 24, len(dek2)) // AES-192
}

func TestListKeys(t *testing.T) {
	db, cleanup := setupTestDatabase(t)
	defer cleanup()

	mek := []byte("01234567890123456789012345678901") // 32 bytes

	manager, err := NewDEKManager(db, mek)
	require.NoError(t, err)
	defer manager.Shutdown()

	ctx := context.Background()

	// Register some keys
	keysToRegister := []string{"key1", "key2", "key3"}
	for _, key := range keysToRegister {
		err = manager.RegisterKey(ctx, key)
		require.NoError(t, err)
	}

	// List the keys
	keys, err := manager.ListKeys(ctx)
	require.NoError(t, err)

	// Check if all registered keys are in the list
	assert.Equal(t, len(keysToRegister), len(keys))
	for _, key := range keysToRegister {
		assert.Contains(t, keys, key)
	}

	// Register another key
	err = manager.RegisterKey(ctx, "key4")
	require.NoError(t, err)

	// List the keys again
	keys, err = manager.ListKeys(ctx)
	require.NoError(t, err)

	// Check if the new key is also in the list
	assert.Equal(t, len(keysToRegister)+1, len(keys))
	assert.Contains(t, keys, "key4")
}

func TestGetKeyInfo(t *testing.T) {
	db, cleanup := setupTestDatabase(t)
	defer cleanup()

	mek := []byte("01234567890123456789012345678901") // 32 bytes

	manager, err := NewDEKManager(db, mek)
	require.NoError(t, err)
	defer manager.Shutdown()

	ctx := context.Background()

	// Register a key
	err = manager.RegisterKey(ctx, "info_key")
	require.NoError(t, err)

	// Get initial key info
	genFuncName, latestVersion, err := manager.GetKeyInfo(ctx, "info_key")
	require.NoError(t, err)
	assert.Equal(t, "aes256-random", genFuncName) // Assuming this is the default
	assert.Equal(t, 0, latestVersion)             // No DEK generated yet

	// Generate a DEK
	_, version, err := manager.GetDEK(ctx, "info_key")
	require.NoError(t, err)
	assert.Equal(t, 1, version)

	// Get key info again
	genFuncName, latestVersion, err = manager.GetKeyInfo(ctx, "info_key")
	require.NoError(t, err)
	assert.Equal(t, "aes256-random", genFuncName)
	assert.Equal(t, 1, latestVersion)

	// Rotate the DEK
	err = manager.RotateDEK(ctx, "info_key")
	require.NoError(t, err)

	// Get key info once more
	genFuncName, latestVersion, err = manager.GetKeyInfo(ctx, "info_key")
	require.NoError(t, err)
	assert.Equal(t, "aes256-random", genFuncName)
	assert.Equal(t, 2, latestVersion)

	// Try to get info for a non-existent key
	_, _, err = manager.GetKeyInfo(ctx, "non_existent_key")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestCustomDEKGenerationFunction(t *testing.T) {
	db, cleanup := setupTestDatabase(t)
	defer cleanup()

	mek := []byte("01234567890123456789012345678901") // 32 bytes

	customFunc := func(ctx context.Context) ([]byte, error) {
		dek := make([]byte, 64) // 512-bit key
		if _, err := io.ReadFull(rand.Reader, dek); err != nil {
			return nil, fmt.Errorf("failed to generate random 512-bit key: %w", err)
		}
		return dek, nil
	}

	manager, err := NewDEKManager(db, mek, WithFunction("custom-512", customFunc))
	require.NoError(t, err)
	defer manager.Shutdown()

	ctx := context.Background()

	// Register a key with the custom function
	err = manager.RegisterKeyWithFunction(ctx, "custom_key", "custom-512")
	require.NoError(t, err)

	// Get the DEK
	dek, version, err := manager.GetDEK(ctx, "custom_key")
	require.NoError(t, err)
	assert.Equal(t, 64, len(dek)) // Should be 512 bits (64 bytes)
	assert.Equal(t, 1, version)

	// Verify key info
	genFuncName, latestVersion, err := manager.GetKeyInfo(ctx, "custom_key")
	require.NoError(t, err)
	assert.Equal(t, "custom-512", genFuncName)
	assert.Equal(t, 1, latestVersion)
}

// Add more tests as needed...
