package gopgdekmanager_test

import (
	"context"
	"database/sql"
	"fmt"
	"github.com/docker/go-connections/nat"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	gopgdekmanager "github.com/tzahifadida/go-pg-dek-manager"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
func TestReadmeExamples(t *testing.T) {
	db, cleanup := setupTestDatabase(t)
	defer cleanup()

	ctx := context.Background()
	mek := []byte("12345678901234567890123456789012") // 32-byte key

	t.Run("Initialization", func(t *testing.T) {
		manager, err := gopgdekmanager.NewDEKManager(db, mek,
			gopgdekmanager.WithCleanupPeriod(180*24*time.Hour),
			gopgdekmanager.WithDEKRotationPeriod(30*24*time.Hour),
		)
		require.NoError(t, err)
		assert.NotNil(t, manager)
		defer manager.Shutdown()
	})

	t.Run("RegisteringAKey", func(t *testing.T) {
		manager, err := gopgdekmanager.NewDEKManager(db, mek)
		require.NoError(t, err)
		defer manager.Shutdown()

		err = manager.RegisterKey(ctx, "user_data")
		require.NoError(t, err)
	})

	t.Run("GettingADEK", func(t *testing.T) {
		manager, err := gopgdekmanager.NewDEKManager(db, mek)
		require.NoError(t, err)
		defer manager.Shutdown()

		err = manager.RegisterKey(ctx, "user_data")
		require.NoError(t, err)

		dek, version, err := manager.GetDEK(ctx, "user_data")
		require.NoError(t, err)
		assert.NotNil(t, dek)
		assert.Equal(t, 1, version)
	})

	t.Run("ManualDEKRotation", func(t *testing.T) {
		manager, err := gopgdekmanager.NewDEKManager(db, mek)
		require.NoError(t, err)
		defer manager.Shutdown()

		err = manager.RegisterKey(ctx, "user_data")
		require.NoError(t, err)

		err = manager.RotateDEK(ctx, "user_data")
		require.NoError(t, err)
	})

	t.Run("GettingASpecificVersionOfADEK", func(t *testing.T) {
		manager, err := gopgdekmanager.NewDEKManager(db, mek)
		require.NoError(t, err)
		defer manager.Shutdown()

		err = manager.RegisterKey(ctx, "user_data")
		require.NoError(t, err)

		// Create initial version
		_, _, err = manager.GetDEK(ctx, "user_data")
		require.NoError(t, err)

		// Rotate to create version 2
		err = manager.RotateDEK(ctx, "user_data")
		require.NoError(t, err)

		dek, err := manager.GetDEKByVersion(ctx, "user_data", 2)
		require.NoError(t, err)
		assert.NotNil(t, dek)
	})

	t.Run("ListingRegisteredKeys", func(t *testing.T) {
		manager, err := gopgdekmanager.NewDEKManager(db, mek)
		require.NoError(t, err)
		defer manager.Shutdown()

		err = manager.RegisterKey(ctx, "key1")
		require.NoError(t, err)
		err = manager.RegisterKey(ctx, "key2")
		require.NoError(t, err)

		keys, err := manager.ListKeys(ctx)
		require.NoError(t, err)
		assert.Contains(t, keys, "key1")
		assert.Contains(t, keys, "key2")
	})

	t.Run("GettingKeyInformation", func(t *testing.T) {
		manager, err := gopgdekmanager.NewDEKManager(db, mek)
		require.NoError(t, err)
		defer manager.Shutdown()

		err = manager.RegisterKey(ctx, "user_data")
		require.NoError(t, err)

		_, _, err = manager.GetDEK(ctx, "user_data")
		require.NoError(t, err)

		genFuncName, latestVersion, err := manager.GetKeyInfo(ctx, "user_data")
		require.NoError(t, err)
		assert.Equal(t, "aes256-random", genFuncName)
		assert.Greater(t, latestVersion, 0, "Latest version should be greater than 0")
		t.Logf("Latest version for 'user_data': %d", latestVersion)
	})
}
