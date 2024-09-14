package gopgdekmanager_test

import (
	"context"
	"database/sql"
	"fmt"
	"github.com/docker/go-connections/nat"
	gopgdekmanager "github.com/tzahifadida/go-pg-dek-manager"
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
func TestReadmeExamples(t *testing.T) {
	db, cleanup := setupTestDatabase(t)
	defer cleanup()

	t.Run("Initialization", func(t *testing.T) {
		mek := []byte("12345678901234567890123456789012") // 32-byte key

		manager, err := gopgdekmanager.NewDEKManager(db, mek,
			gopgdekmanager.WithCleanupPeriod(180*24*time.Hour),
			gopgdekmanager.WithDEKRotationPeriod(30*24*time.Hour),
		)
		require.NoError(t, err)
		assert.NotNil(t, manager)
		defer manager.Shutdown()
	})

	t.Run("Getting and Using a DEK", func(t *testing.T) {
		mek := []byte("12345678901234567890123456789012") // 32-byte key

		manager, err := gopgdekmanager.NewDEKManager(db, mek)
		require.NoError(t, err)
		defer manager.Shutdown()

		dek, version, err := manager.GetDEK("user_data")
		require.NoError(t, err)
		assert.NotNil(t, dek)
		assert.Equal(t, 1, version)
		assert.Len(t, dek, 32) // Ensure DEK is 32 bytes (256 bits)

		// Simulate using the DEK for encryption (in a real scenario, you'd use a proper encryption library)
		plaintext := []byte("This is a secret message")
		encryptedData := make([]byte, len(plaintext))
		for i := range plaintext {
			encryptedData[i] = plaintext[i] ^ dek[i%len(dek)]
		}

		// Retrieve the same DEK again
		sameDEK, sameVersion, err := manager.GetDEK("user_data")
		require.NoError(t, err)
		assert.Equal(t, dek, sameDEK)
		assert.Equal(t, version, sameVersion)

		// Simulate decryption
		decryptedData := make([]byte, len(encryptedData))
		for i := range encryptedData {
			decryptedData[i] = encryptedData[i] ^ sameDEK[i%len(sameDEK)]
		}

		assert.Equal(t, plaintext, decryptedData) // The decrypted data should match the original plaintext
	})

	t.Run("Manual DEK Rotation", func(t *testing.T) {
		mek := []byte("12345678901234567890123456789012") // 32-byte key

		manager, err := gopgdekmanager.NewDEKManager(db, mek)
		require.NoError(t, err)
		defer manager.Shutdown()

		// Get initial DEK
		dek1, version1, err := manager.GetDEK("rotate_example")
		require.NoError(t, err)

		// Rotate DEK
		err = manager.RotateDEK("rotate_example")
		require.NoError(t, err)

		// Get rotated DEK
		dek2, version2, err := manager.GetDEK("rotate_example")
		require.NoError(t, err)

		assert.NotEqual(t, dek1, dek2)
		assert.Equal(t, version1+1, version2)
	})
}
