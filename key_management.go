package gopgdekmanager

import (
	"container/list"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/jmoiron/sqlx"
)

const (
	createSchemaSQL   = `CREATE SCHEMA IF NOT EXISTS "%s"`
	createMEKTableSQL = `
		CREATE TABLE IF NOT EXISTS "%s"."%s_mek" (
			"id" SERIAL PRIMARY KEY,
			"mek_hash" TEXT NOT NULL UNIQUE,
			"created_at" TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		);
	`
	createDEKTableSQL = `
		CREATE TABLE IF NOT EXISTS "%s"."%s_dek" (
			"id" SERIAL PRIMARY KEY,
			"version" INTEGER NOT NULL,
			"key_name" TEXT NOT NULL,
			"encrypted_dek" TEXT NOT NULL,
			"mek_id" INTEGER NOT NULL REFERENCES "%s"."%s_mek"("id"),
			"created_at" TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			UNIQUE ("version", "key_name", "mek_id")
		);
		CREATE INDEX IF NOT EXISTS "%s_dek_key_name_mek_id_idx" ON "%s"."%s_dek" ("key_name", "mek_id");
	`
	createLockTableSQL = `
		CREATE TABLE IF NOT EXISTS "%s"."%s_locks" (
			"lock_name" TEXT PRIMARY KEY,
			"locked_at" TIMESTAMP NOT NULL,
			"lease_until" TIMESTAMP NOT NULL
		);
	`
)

// MinimalLogger is an interface for minimal logging functionality.
type MinimalLogger interface {
	Warn(msg string, args ...any)
}

// DEKManager handles the management of Data Encryption Keys (DEKs).
type DEKManager struct {
	db                    *sqlx.DB
	mek                   []byte
	oldMEK                []byte
	currentMEKID          int
	oldMEKID              int
	isCurrentMEK          bool
	schemaName            string
	tablePrefix           string
	caches                map[string]*lruCache
	cacheMutex            sync.RWMutex
	maxCacheSize          int
	cacheExpiration       time.Duration
	cleanupPeriod         *time.Duration
	dekRotationPeriod     time.Duration
	transitionCheckPeriod time.Duration
	ctx                   context.Context
	cancel                context.CancelFunc
	logger                MinimalLogger
	lockLeaseDuration     time.Duration
	wg                    sync.WaitGroup
}

// DEKManagerConfig holds configuration options for DEKManager.
type DEKManagerConfig struct {
	DB                    *sql.DB
	MEK                   []byte
	OldMEK                []byte
	SchemaName            string
	TablePrefix           string
	CleanupPeriod         *time.Duration
	DEKRotationPeriod     time.Duration
	TransitionCheckPeriod time.Duration
	LockLeaseDuration     time.Duration
	Logger                MinimalLogger
	MaxCacheSize          int
	CacheExpiration       time.Duration
	DriverName            string
}

// DEKManagerOption is a function type for configuring a DEKManager.
type DEKManagerOption func(*DEKManagerConfig)

// WithCleanupPeriod sets the period for cleaning up old DEKs.
//
// Parameters:
//   - d: The duration between cleanup operations.
func WithCleanupPeriod(d time.Duration) DEKManagerOption {
	return func(c *DEKManagerConfig) {
		c.CleanupPeriod = &d
	}
}

// WithDEKRotationPeriod sets the period for automatic DEK rotation.
//
// Parameters:
//   - d: The duration between DEK rotation operations.
func WithDEKRotationPeriod(d time.Duration) DEKManagerOption {
	return func(c *DEKManagerConfig) {
		c.DEKRotationPeriod = d
	}
}

// WithTransitionCheckPeriod sets the period for checking MEK transitions.
//
// Parameters:
//   - d: The duration between MEK transition checks.
func WithTransitionCheckPeriod(d time.Duration) DEKManagerOption {
	return func(c *DEKManagerConfig) {
		c.TransitionCheckPeriod = d
	}
}

// WithTablePrefix sets a custom table prefix for database tables.
//
// Parameters:
//   - prefix: The prefix to be used for table names.
func WithTablePrefix(prefix string) DEKManagerOption {
	return func(c *DEKManagerConfig) {
		c.TablePrefix = prefix
	}
}

// WithSchemaName sets a custom schema name for database tables.
//
// Parameters:
//   - schema: The schema name to be used.
func WithSchemaName(schema string) DEKManagerOption {
	return func(c *DEKManagerConfig) {
		c.SchemaName = schema
	}
}

// WithLogger provides a custom logger implementation.
//
// Parameters:
//   - logger: The logger implementing the MinimalLogger interface.
func WithLogger(logger MinimalLogger) DEKManagerOption {
	return func(c *DEKManagerConfig) {
		c.Logger = logger
	}
}

// WithLockLeaseDuration sets the duration for distributed locks.
//
// Parameters:
//   - d: The duration for which a lock is considered valid.
func WithLockLeaseDuration(d time.Duration) DEKManagerOption {
	return func(c *DEKManagerConfig) {
		c.LockLeaseDuration = d
	}
}

// WithOldMEK provides an old MEK for transition scenarios.
//
// Parameters:
//   - oldMEK: The old Master Encryption Key as a byte slice.
func WithOldMEK(oldMEK []byte) DEKManagerOption {
	return func(c *DEKManagerConfig) {
		c.OldMEK = oldMEK
	}
}

// WithMaxCacheSize sets the maximum size for the in-memory DEK cache.
//
// Parameters:
//   - size: The maximum number of DEKs to cache in memory.
func WithMaxCacheSize(size int) DEKManagerOption {
	return func(c *DEKManagerConfig) {
		c.MaxCacheSize = size
	}
}

// WithCacheExpiration sets the expiration duration for cached DEKs.
//
// Parameters:
//   - d: The duration after which a cached DEK is considered expired.
func WithCacheExpiration(d time.Duration) DEKManagerOption {
	return func(c *DEKManagerConfig) {
		c.CacheExpiration = d
	}
}

// WithDriverName sets the database driver name.
//
// Parameters:
//   - driverName: The name of the database driver to use.
func WithDriverName(driverName string) DEKManagerOption {
	return func(c *DEKManagerConfig) {
		c.DriverName = driverName
	}
}

// NewDEKManager creates a new DEK manager with the given database connection and MEK.
//
// Parameters:
//   - db: A sql.DB object representing the database connection.
//   - mek: The Master Encryption Key as a byte slice (must be 32 bytes).
//   - options: Optional configuration options for the DEK manager.
//
// Returns:
//   - *DEKManager: A pointer to the created DEKManager.
//   - error: An error if the creation fails.
func NewDEKManager(db *sql.DB, mek []byte, options ...DEKManagerOption) (*DEKManager, error) {
	if len(mek) != 32 {
		return nil, fmt.Errorf("invalid MEK size: must be 32 bytes")
	}

	config := &DEKManagerConfig{
		DB:                    db,
		MEK:                   mek,
		SchemaName:            "public",
		TablePrefix:           "dek_store",
		DEKRotationPeriod:     90 * 24 * time.Hour, // 3 months default
		TransitionCheckPeriod: time.Hour,           // 1 hour default
		LockLeaseDuration:     3 * time.Minute,
		Logger:                newDefaultLogger(),
		MaxCacheSize:          1000,           // Default cache size
		CacheExpiration:       24 * time.Hour, // Default cache expiration (24 hours)
		DriverName:            "pgx",          // Default driver name
	}

	for _, option := range options {
		option(config)
	}

	sqlxDB := sqlx.NewDb(config.DB, config.DriverName)

	ctx, cancel := context.WithCancel(context.Background())

	manager := &DEKManager{
		db:                    sqlxDB,
		mek:                   config.MEK,
		oldMEK:                config.OldMEK,
		schemaName:            config.SchemaName,
		tablePrefix:           config.TablePrefix,
		maxCacheSize:          config.MaxCacheSize,
		cacheExpiration:       config.CacheExpiration,
		caches:                make(map[string]*lruCache),
		cleanupPeriod:         config.CleanupPeriod,
		dekRotationPeriod:     config.DEKRotationPeriod,
		transitionCheckPeriod: config.TransitionCheckPeriod,
		ctx:                   ctx,
		cancel:                cancel,
		logger:                config.Logger,
		lockLeaseDuration:     config.LockLeaseDuration,
	}

	if err := manager.initializeDB(); err != nil {
		return nil, fmt.Errorf("failed to initialize database: %w", err)
	}

	if err := manager.initializeOrValidateMEK(); err != nil {
		return nil, fmt.Errorf("failed to initialize or validate MEK: %w", err)
	}

	manager.wg.Add(2) // Add wait group for goroutines
	go manager.periodicCleanup()
	go manager.periodicDEKRotation()

	if manager.oldMEK != nil {
		if err := manager.initializeOldMEK(); err != nil {
			return nil, fmt.Errorf("failed to initialize old MEK: %w", err)
		}
		if err := manager.transitionToNewMEK(); err != nil {
			return nil, fmt.Errorf("failed to transition to new MEK: %w", err)
		}
		manager.wg.Add(1)
		go manager.periodicTransitionCheck()
	}

	return manager, nil
}

func (dm *DEKManager) initializeDB() error {
	ctx := context.Background()
	tx, err := dm.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	_, err = tx.ExecContext(ctx, fmt.Sprintf(createSchemaSQL, dm.schemaName))
	if err != nil {
		return fmt.Errorf("failed to create schema: %w", err)
	}
	_, err = tx.ExecContext(ctx, fmt.Sprintf(createMEKTableSQL, dm.schemaName, dm.tablePrefix))
	if err != nil {
		return fmt.Errorf("failed to create MEK table: %w", err)
	}
	_, err = tx.ExecContext(ctx, fmt.Sprintf(createDEKTableSQL, dm.schemaName, dm.tablePrefix, dm.schemaName, dm.tablePrefix, dm.tablePrefix, dm.schemaName, dm.tablePrefix))
	if err != nil {
		return fmt.Errorf("failed to create DEK table: %w", err)
	}
	_, err = tx.ExecContext(ctx, fmt.Sprintf(createLockTableSQL, dm.schemaName, dm.tablePrefix))
	if err != nil {
		return fmt.Errorf("failed to create lock table: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

func (dm *DEKManager) initializeOrValidateMEK() error {
	ctx := context.Background()
	tx, err := dm.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	mekHash := dm.hashMEK(dm.mek)

	var id int
	var isCurrentMEK bool
	err = tx.QueryRowContext(ctx, fmt.Sprintf(`
		SELECT id, (id = (SELECT MAX(id) FROM "%s"."%s_mek")) AS is_current_mek
		FROM "%s"."%s_mek"
		WHERE mek_hash = $1
	`, dm.schemaName, dm.tablePrefix, dm.schemaName, dm.tablePrefix), mekHash).Scan(&id, &isCurrentMEK)

	if err == sql.ErrNoRows {
		// MEK not found in the database
		if dm.oldMEK != nil {
			// We're transitioning to a new MEK
			var oldMEKID int
			err = tx.QueryRowContext(ctx, fmt.Sprintf(`
				SELECT id FROM "%s"."%s_mek"
				WHERE mek_hash = $1
			`, dm.schemaName, dm.tablePrefix), dm.hashMEK(dm.oldMEK)).Scan(&oldMEKID)
			if err != nil {
				return fmt.Errorf("failed to find old MEK: %w", err)
			}

			// Check if old MEK is the current MEK
			var isOldMEKCurrent bool
			err = tx.QueryRowContext(ctx, fmt.Sprintf(`
				SELECT id = (SELECT MAX(id) FROM "%s"."%s_mek")
				FROM "%s"."%s_mek"
				WHERE id = $1
			`, dm.schemaName, dm.tablePrefix, dm.schemaName, dm.tablePrefix), oldMEKID).Scan(&isOldMEKCurrent)
			if err != nil {
				return fmt.Errorf("failed to check if old MEK is current: %w", err)
			}

			if isOldMEKCurrent {
				// Old MEK is current, we can create the new MEK
				if err := dm.createNewMEKEntry(ctx, tx, mekHash); err != nil {
					return err
				}
			} else {
				return errors.New("old MEK is not the current MEK")
			}
		} else {
			// No old MEK provided, check if there are any existing DEKs
			var count int
			err = tx.QueryRowContext(ctx, fmt.Sprintf(`
				SELECT COUNT(*) FROM "%s"."%s_dek"
			`, dm.schemaName, dm.tablePrefix)).Scan(&count)
			if err != nil {
				return fmt.Errorf("failed to check existing DEKs: %w", err)
			}
			if count > 0 {
				return errors.New("provided MEK does not match existing encrypted DEKs")
			}

			// No existing DEKs, create a new MEK entry
			if err := dm.createNewMEKEntry(ctx, tx, mekHash); err != nil {
				return err
			}
		}
	} else if err != nil {
		return fmt.Errorf("failed to query MEK: %w", err)
	} else {
		dm.currentMEKID = id
		dm.isCurrentMEK = isCurrentMEK

		if !isCurrentMEK {
			dm.logger.Warn("Using an old version of MEK. Key rotations will be blocked.", "mek_id", id)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

func (dm *DEKManager) createNewMEKEntry(ctx context.Context, tx *sql.Tx, mekHash string) error {
	err := tx.QueryRowContext(ctx, fmt.Sprintf(`
            		INSERT INTO "%s"."%s_mek" (mek_hash) 
            		VALUES ($1) 
            		RETURNING id
            	`, dm.schemaName, dm.tablePrefix), mekHash).Scan(&dm.currentMEKID)

	if err != nil {
		return fmt.Errorf("failed to create new MEK entry: %w", err)
	}

	dm.isCurrentMEK = true
	return nil
}

func (dm *DEKManager) initializeOldMEK() error {
	ctx := context.Background()
	tx, err := dm.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	oldMEKHash := dm.hashMEK(dm.oldMEK)
	err = tx.QueryRowContext(ctx, fmt.Sprintf(`
            		SELECT id FROM "%s"."%s_mek"
            		WHERE mek_hash = $1
            	`, dm.schemaName, dm.tablePrefix), oldMEKHash).Scan(&dm.oldMEKID)

	if err != nil {
		return fmt.Errorf("failed to find old MEK: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

func (dm *DEKManager) hashMEK(mek []byte) string {
	hash := sha256.Sum256(mek)
	return base64.StdEncoding.EncodeToString(hash[:])
}

func (dm *DEKManager) transitionToNewMEK() error {
	dm.logger.Warn("Starting MEK transition")

	tx, err := dm.db.BeginTxx(dm.ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() {
		if p := recover(); p != nil {
			tx.Rollback()
			panic(p)
		}
	}()

	// Fetch old DEKs
	oldDEKs, err := dm.fetchOldDEKs(tx)
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("failed to fetch old DEKs: %w", err)
	}

	// Create new DEK versions
	for _, oldDEK := range oldDEKs {
		if err := dm.createNewDEKVersionWithinTx(tx, oldDEK.keyName, oldDEK.encryptedDEK, oldDEK.version); err != nil {
			tx.Rollback()
			return fmt.Errorf("failed to create new DEK version for key %s: %w", oldDEK.keyName, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	dm.logger.Warn("MEK transition completed successfully")
	return nil
}

type oldDEKInfo struct {
	keyName      string
	encryptedDEK string
	version      int
}

func (dm *DEKManager) fetchOldDEKs(tx *sqlx.Tx) ([]oldDEKInfo, error) {
	query := fmt.Sprintf(`
            		SELECT key_name, encrypted_dek, version
            		FROM "%s"."%s_dek" 
            		WHERE mek_id = $1
            		ORDER BY key_name, version
            	`, dm.schemaName, dm.tablePrefix)

	rows, err := tx.QueryxContext(dm.ctx, query, dm.oldMEKID)
	if err != nil {
		return nil, fmt.Errorf("failed to query old DEKs: %w", err)
	}
	defer rows.Close()

	var oldDEKs []oldDEKInfo
	for rows.Next() {
		var dek oldDEKInfo
		if err := rows.Scan(&dek.keyName, &dek.encryptedDEK, &dek.version); err != nil {
			return nil, fmt.Errorf("failed to scan old DEK: %w", err)
		}
		oldDEKs = append(oldDEKs, dek)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating over old DEKs: %w", err)
	}

	return oldDEKs, nil
}

func (dm *DEKManager) createNewDEKVersionWithinTx(tx *sqlx.Tx, keyName, oldEncryptedDEK string, oldVersion int) error {
	dm.logger.Warn(fmt.Sprintf("Creating new DEK version for key: %s, version: %d", keyName, oldVersion))

	// Decrypt DEK with old MEK
	dek, err := dm.decryptDEKWithMEK(dm.oldMEK, oldEncryptedDEK)
	if err != nil {
		return fmt.Errorf("failed to decrypt old DEK: %w", err)
	}

	// Re-encrypt DEK with new MEK
	newEncryptedDEK, err := dm.encryptDEK(dek)
	if err != nil {
		return fmt.Errorf("failed to re-encrypt DEK: %w", err)
	}

	// Store new DEK version
	query := fmt.Sprintf(`
            		INSERT INTO "%s"."%s_dek" (key_name, encrypted_dek, mek_id, version)
            		VALUES ($1, $2, $3, $4)
            		ON CONFLICT (key_name, version, mek_id) DO NOTHING
            	`, dm.schemaName, dm.tablePrefix)

	_, err = tx.ExecContext(dm.ctx, query, keyName, newEncryptedDEK, dm.currentMEKID, oldVersion)
	if err != nil {
		return fmt.Errorf("failed to store re-encrypted DEK: %w", err)
	}

	dm.logger.Warn(fmt.Sprintf("Successfully created new DEK version for key: %s, version: %d", keyName, oldVersion))
	return nil
}

// GetDEK retrieves or creates a DEK for the given key name.
//
// Parameters:
//   - keyName: The name of the key to retrieve or create.
//
// Returns:
//   - []byte: The DEK as a byte slice.
//   - int: The version of the DEK.
//   - error: An error if the operation fails.
func (dm *DEKManager) GetDEK(keyName string) ([]byte, int, error) {
	if !dm.isCurrentMEK {
		dm.logger.Warn("Using an old version of MEK to retrieve DEK.", "key_name", keyName)
	}

	// Try to get from cache first
	if cachedDEK, cachedVersion, found := dm.getFromCache(keyName); found {
		return cachedDEK, cachedVersion, nil
	}

	ctx := context.Background()
	tx, err := dm.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	var id int
	var version int
	var encryptedDEK string
	var mekID int

	err = tx.QueryRowContext(ctx, fmt.Sprintf(`
            		SELECT id, version, encrypted_dek, mek_id 
            		FROM "%s"."%s_dek" 
            		WHERE key_name = $1 AND mek_id = $2
            		ORDER BY version DESC LIMIT 1
            	`, dm.schemaName, dm.tablePrefix), keyName, dm.currentMEKID).Scan(&id, &version, &encryptedDEK, &mekID)

	if err == sql.ErrNoRows {
		if !dm.isCurrentMEK {
			return nil, 0, errors.New("cannot create new DEK with old MEK")
		}
		// No DEK found, generate and store a new one within this transaction
		dek, newVersion, err := dm.generateAndStoreDEKWithinTx(ctx, tx, keyName)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to generate and store new DEK: %w", err)
		}
		if err := tx.Commit(); err != nil {
			return nil, 0, fmt.Errorf("failed to commit transaction: %w", err)
		}
		dm.addToCache(keyName, newVersion, dek)
		return dek, newVersion, nil
	} else if err != nil {
		return nil, 0, fmt.Errorf("failed to query DEK: %w", err)
	}

	dek, err := dm.decryptDEK(encryptedDEK)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to decrypt DEK: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, 0, fmt.Errorf("failed to commit transaction: %w", err)
	}

	// Add to cache
	dm.addToCache(keyName, version, dek)

	return dek, version, nil
}

func (dm *DEKManager) generateAndStoreDEKWithinTx(ctx context.Context, tx *sql.Tx, keyName string) ([]byte, int, error) {
	dek := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return nil, 0, fmt.Errorf("failed to generate random DEK: %w", err)
	}

	encryptedDEK, err := dm.encryptDEK(dek)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to encrypt DEK: %w", err)
	}

	var version int
	err = tx.QueryRowContext(ctx, fmt.Sprintf(`
            		INSERT INTO "%s"."%s_dek" (version, key_name, encrypted_dek, mek_id) 
            		VALUES (
            			(SELECT COALESCE(MAX(version), 0) + 1 FROM "%s"."%s_dek" WHERE key_name = $1),
            			$1, $2, $3
            		) RETURNING version
            	`, dm.schemaName, dm.tablePrefix, dm.schemaName, dm.tablePrefix), keyName, encryptedDEK, dm.currentMEKID).Scan(&version)

	if err != nil {
		return nil, 0, fmt.Errorf("failed to insert new DEK: %w", err)
	}

	return dek, version, nil
}

func (dm *DEKManager) encryptDEK(dek []byte) (string, error) {
	block, err := aes.NewCipher(dm.mek)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, dek, nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func (dm *DEKManager) decryptDEK(encryptedDEK string) ([]byte, error) {
	return dm.decryptDEKWithMEK(dm.mek, encryptedDEK)
}

func (dm *DEKManager) decryptDEKWithMEK(mek []byte, encryptedDEK string) ([]byte, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(encryptedDEK)
	if err != nil {
		return nil, fmt.Errorf("failed to decode encrypted DEK: %w", err)
	}

	block, err := aes.NewCipher(mek)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	if len(ciphertext) < gcm.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt DEK: %w", err)
	}

	return plaintext, nil
}

// RotateDEK rotates the DEK for the given key name.
//
// Parameters:
//   - keyName: The name of the key to rotate.
//
// Returns:
//   - error: An error if the rotation fails.
func (dm *DEKManager) RotateDEK(keyName string) error {
	if !dm.isCurrentMEK {
		return errors.New("cannot rotate DEK with an old version of MEK")
	}

	ctx := context.Background()
	tx, err := dm.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	lockName := fmt.Sprintf("dek_rotation_%s", keyName)
	locked, err := dm.acquireLock(ctx, tx, lockName)
	if err != nil {
		return fmt.Errorf("failed to acquire lock: %w", err)
	}
	if !locked {
		return errors.New("failed to acquire lock for DEK rotation")
	}

	// Use a named return value to handle errors and lock release
	var rotationErr error
	defer func() {
		unlockErr := dm.releaseLock(ctx, tx, lockName)
		if unlockErr != nil {
			if rotationErr != nil {
				// If there was already an error, log the unlock error
				dm.logger.Warn("Failed to release lock after error", "error", unlockErr)
			} else {
				// If there wasn't an error yet, set the unlock error as the return error
				rotationErr = fmt.Errorf("failed to release lock: %w", unlockErr)
			}
		}

		if rotationErr == nil {
			// Only commit if there were no errors
			if commitErr := tx.Commit(); commitErr != nil {
				rotationErr = fmt.Errorf("failed to commit transaction: %w", commitErr)
			}
		}
	}()

	dek, version, err := dm.generateAndStoreDEKWithinTx(ctx, tx, keyName)
	if err != nil {
		rotationErr = fmt.Errorf("failed to generate and store new DEK: %w", err)
		return rotationErr
	}

	// If we reach here, the rotation was successful
	// The deferred function will handle committing and potential errors

	// Add the latest version to the cache if everything was successful
	if rotationErr == nil {
		dm.addToCache(keyName, version, dek)
	}

	return rotationErr
}

func (dm *DEKManager) acquireLock(ctx context.Context, tx *sql.Tx, lockName string) (bool, error) {
	var locked bool
	err := tx.QueryRowContext(ctx, fmt.Sprintf(`
		INSERT INTO "%s"."%s_locks" (lock_name, locked_at, lease_until)
		VALUES ($1, NOW(), NOW() + $2::INTERVAL)
		ON CONFLICT (lock_name) DO UPDATE
		SET locked_at = NOW(), lease_until = NOW() + $2::INTERVAL
		WHERE "%s_locks".lease_until < NOW()
		RETURNING true
	`, dm.schemaName, dm.tablePrefix, dm.tablePrefix), lockName, dm.lockLeaseDuration.String()).Scan(&locked)

	if err == sql.ErrNoRows {
		return false, nil
	} else if err != nil {
		return false, fmt.Errorf("failed to acquire lock: %w", err)
	}

	return locked, nil
}

func (dm *DEKManager) releaseLock(ctx context.Context, tx *sql.Tx, lockName string) error {
	_, err := tx.ExecContext(ctx, fmt.Sprintf(`
		DELETE FROM "%s"."%s_locks"
		WHERE lock_name = $1
	`, dm.schemaName, dm.tablePrefix), lockName)
	if err != nil {
		return fmt.Errorf("failed to release lock: %w", err)
	}
	return nil
}

func (dm *DEKManager) periodicDEKRotation() {
	defer dm.wg.Done()
	ticker := time.NewTicker(dm.dekRotationPeriod)
	defer ticker.Stop()

	for {
		select {
		case <-dm.ctx.Done():
			return
		case <-ticker.C:
			if err := dm.rotateAllDEKs(); err != nil {
				dm.logger.Warn("Error rotating DEKs", "error", err)
			}
		}
	}
}

func (dm *DEKManager) rotateAllDEKs() error {
	ctx := context.Background()
	tx, err := dm.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	rows, err := tx.QueryContext(ctx, fmt.Sprintf(`
		SELECT DISTINCT key_name 
		FROM "%s"."%s_dek"
		WHERE mek_id = $1
	`, dm.schemaName, dm.tablePrefix), dm.currentMEKID)
	if err != nil {
		return fmt.Errorf("failed to query existing key names: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var keyName string
		if err := rows.Scan(&keyName); err != nil {
			return fmt.Errorf("failed to scan key name: %w", err)
		}
		if err := dm.RotateDEK(keyName); err != nil {
			dm.logger.Warn("Error rotating DEK", "key_name", keyName, "error", err)
		}
	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf("error iterating over key names: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

func (dm *DEKManager) periodicCleanup() {
	defer dm.wg.Done()
	if dm.cleanupPeriod == nil {
		return // No cleanup if period is not set
	}

	ticker := time.NewTicker(*dm.cleanupPeriod)
	defer ticker.Stop()

	for {
		select {
		case <-dm.ctx.Done():
			return
		case <-ticker.C:
			if err := dm.cleanupOldDEKs(); err != nil {
				dm.logger.Warn("Error during cleanup", "error", err)
			}
		}
	}
}

func (dm *DEKManager) cleanupOldDEKs() error {
	ctx := context.Background()
	tx, err := dm.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Exclude current MEK and old MEK (if present) from cleanup
	excludedMEKs := []int{dm.currentMEKID}
	if dm.oldMEKID != 0 {
		excludedMEKs = append(excludedMEKs, dm.oldMEKID)
	}

	query, args, err := sqlx.In(fmt.Sprintf(`
		DELETE FROM "%s"."%s_dek"
		WHERE mek_id IN (
			SELECT id FROM "%s"."%s_mek"
			WHERE created_at < ? AND id NOT IN (?)
		)
	`, dm.schemaName, dm.tablePrefix, dm.schemaName, dm.tablePrefix), time.Now().Add(-*dm.cleanupPeriod), excludedMEKs)
	if err != nil {
		return fmt.Errorf("failed to construct IN query: %w", err)
	}

	query = dm.db.Rebind(query)
	_, err = tx.ExecContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("failed to cleanup old DEKs: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// RemoveDEKs removes DEKs for the given key name up to the specified version.
//
// Parameters:
//   - keyName: The name of the key to remove DEKs for.
//   - upToVersion: The maximum version (inclusive) to remove.
//
// Returns:
//   - error: An error if the removal fails.
func (dm *DEKManager) RemoveDEKs(keyName string, upToVersion int) error {
	ctx := context.Background()
	tx, err := dm.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	_, err = tx.ExecContext(ctx, fmt.Sprintf(`
		DELETE FROM "%s"."%s_dek"
		WHERE key_name = $1 AND version <= $2
	`, dm.schemaName, dm.tablePrefix), keyName, upToVersion)
	if err != nil {
		return fmt.Errorf("failed to remove DEKs: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

func (dm *DEKManager) periodicTransitionCheck() {
	defer dm.wg.Done()
	ticker := time.NewTicker(dm.transitionCheckPeriod)
	defer ticker.Stop()

	for {
		select {
		case <-dm.ctx.Done():
			return
		case <-ticker.C:
			if dm.oldMEK != nil {
				if err := dm.transitionToNewMEK(); err != nil {
					dm.logger.Warn("Error during periodic transition check", "error", err)
				}
			}
		}
	}
}

type lruCache struct {
	keys     map[int]*list.Element
	list     *list.List
	capacity int
}

type cacheItem struct {
	key       int
	value     []byte
	timestamp time.Time
}

func (dm *DEKManager) getFromCache(keyName string) ([]byte, int, bool) {
	dm.cacheMutex.RLock()
	defer dm.cacheMutex.RUnlock()

	if cache, ok := dm.caches[keyName]; ok {
		if item := cache.list.Back(); item != nil {
			cacheItem := item.Value.(*cacheItem)
			if time.Since(cacheItem.timestamp) < dm.cacheExpiration {
				return cacheItem.value, cacheItem.key, true
			}
		}
	}

	return nil, 0, false
}

func (dm *DEKManager) addToCache(keyName string, version int, dek []byte) {
	dm.cacheMutex.Lock()
	defer dm.cacheMutex.Unlock()

	cache, ok := dm.caches[keyName]
	if !ok {
		cache = &lruCache{
			keys:     make(map[int]*list.Element),
			list:     list.New(),
			capacity: dm.maxCacheSize,
		}
		dm.caches[keyName] = cache
	}

	if elem, exists := cache.keys[version]; exists {
		cache.list.MoveToBack(elem)
		item := elem.Value.(*cacheItem)
		item.value = dek
		item.timestamp = time.Now()
	} else {
		if cache.list.Len() >= cache.capacity {
			oldest := cache.list.Front()
			if oldest != nil {
				delete(cache.keys, oldest.Value.(*cacheItem).key)
				cache.list.Remove(oldest)
			}
		}
		item := &cacheItem{key: version, value: dek, timestamp: time.Now()}
		elem := cache.list.PushBack(item)
		cache.keys[version] = elem
	}
}

// Shutdown gracefully shuts down the DEK manager.
func (dm *DEKManager) Shutdown() {
	dm.cancel()

	// Wait for goroutines to finish with a timeout
	done := make(chan struct{})
	go func() {
		dm.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// All goroutines finished
	case <-time.After(20 * time.Second):
		// Timeout occurred
		dm.logger.Warn("Shutdown timed out after 20 seconds")
	}

	// Additional 2-second wait after goroutines finish or timeout
	time.Sleep(2 * time.Second)
}

// SchemaName returns the schema name used by the DEK manager.
//
// Returns:
//   - string: The schema name.
func (dm *DEKManager) SchemaName() string {
	return dm.schemaName
}

// TablePrefix returns the table prefix used by the DEK manager.
//
// Returns:
//   - string: The table prefix.
func (dm *DEKManager) TablePrefix() string {
	return dm.tablePrefix
}

// defaultLogger provides a slog-based implementation of MinimalLogger
type defaultLogger struct {
	logger *slog.Logger
}

func newDefaultLogger() *defaultLogger {
	return &defaultLogger{
		logger: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
			Level: slog.LevelWarn,
		})),
	}
}

func (l *defaultLogger) Warn(msg string, args ...any) {
	l.logger.Warn(msg, args...)
}
