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
	createKeyInfoTableSQL = `
		CREATE TABLE IF NOT EXISTS "%s"."%s_key_info" (
			"key_name" TEXT PRIMARY KEY,
			"gen_func_name" TEXT NOT NULL
		);
	`
)

type MinimalLogger interface {
	Warn(msg string, args ...any)
}

type DEKGenerationFunc func(ctx context.Context) ([]byte, error)

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
	dekGenFuncs           map[string]DEKGenerationFunc
	dekGenMutex           sync.RWMutex
	defaultGenFuncName    string
	keyFuncCache          *keyFuncCache
}

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
	DEKGenFuncs           map[string]DEKGenerationFunc
	DefaultGenFuncName    string
	MaxKeyFuncCache       int
}

type DEKManagerOption func(*DEKManagerConfig)

type cacheItem struct {
	key       int
	value     []byte
	timestamp time.Time
}

type lruCache struct {
	capacity int
	items    map[int]*list.Element
	list     *list.List
	mutex    sync.RWMutex
}

type keyFuncCacheItem struct {
	key   string
	value string
}

type keyFuncCache struct {
	capacity int
	items    map[string]*list.Element
	list     *list.List
	mutex    sync.RWMutex
}

func newLRUCache(capacity int) *lruCache {
	return &lruCache{
		capacity: capacity,
		items:    make(map[int]*list.Element),
		list:     list.New(),
	}
}

func (c *lruCache) Get(key int) ([]byte, bool) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	if element, found := c.items[key]; found {
		c.list.MoveToFront(element)
		return element.Value.(*cacheItem).value, true
	}
	return nil, false
}

func (c *lruCache) Add(key int, value []byte) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if element, found := c.items[key]; found {
		c.list.MoveToFront(element)
		element.Value.(*cacheItem).value = value
		element.Value.(*cacheItem).timestamp = time.Now()
		return
	}
	if c.list.Len() >= c.capacity {
		oldest := c.list.Back()
		if oldest != nil {
			delete(c.items, oldest.Value.(*cacheItem).key)
			c.list.Remove(oldest)
		}
	}
	element := c.list.PushFront(&cacheItem{key: key, value: value, timestamp: time.Now()})
	c.items[key] = element
}

func (c *lruCache) Remove(key int) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if element, found := c.items[key]; found {
		delete(c.items, key)
		c.list.Remove(element)
	}
}

func newKeyFuncCache(capacity int) *keyFuncCache {
	return &keyFuncCache{
		capacity: capacity,
		items:    make(map[string]*list.Element),
		list:     list.New(),
	}
}

func (c *keyFuncCache) Get(key string) (string, bool) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	if element, found := c.items[key]; found {
		c.list.MoveToFront(element)
		return element.Value.(*keyFuncCacheItem).value, true
	}
	return "", false
}

func (c *keyFuncCache) Add(key, value string) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if element, found := c.items[key]; found {
		c.list.MoveToFront(element)
		element.Value.(*keyFuncCacheItem).value = value
		return
	}
	if c.list.Len() >= c.capacity {
		oldest := c.list.Back()
		if oldest != nil {
			delete(c.items, oldest.Value.(*keyFuncCacheItem).key)
			c.list.Remove(oldest)
		}
	}
	element := c.list.PushFront(&keyFuncCacheItem{key: key, value: value})
	c.items[key] = element
}

func (c *keyFuncCache) Remove(key string) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if element, found := c.items[key]; found {
		delete(c.items, key)
		c.list.Remove(element)
	}
}

func WithCleanupPeriod(d time.Duration) DEKManagerOption {
	return func(c *DEKManagerConfig) {
		c.CleanupPeriod = &d
	}
}

func WithDEKRotationPeriod(d time.Duration) DEKManagerOption {
	return func(c *DEKManagerConfig) {
		c.DEKRotationPeriod = d
	}
}

func WithTransitionCheckPeriod(d time.Duration) DEKManagerOption {
	return func(c *DEKManagerConfig) {
		c.TransitionCheckPeriod = d
	}
}

func WithTablePrefix(prefix string) DEKManagerOption {
	return func(c *DEKManagerConfig) {
		c.TablePrefix = prefix
	}
}

func WithSchemaName(schema string) DEKManagerOption {
	return func(c *DEKManagerConfig) {
		c.SchemaName = schema
	}
}

func WithLogger(logger MinimalLogger) DEKManagerOption {
	return func(c *DEKManagerConfig) {
		c.Logger = logger
	}
}

func WithLockLeaseDuration(d time.Duration) DEKManagerOption {
	return func(c *DEKManagerConfig) {
		c.LockLeaseDuration = d
	}
}

func WithOldMEK(oldMEK []byte) DEKManagerOption {
	return func(c *DEKManagerConfig) {
		c.OldMEK = oldMEK
	}
}

func WithMaxCacheSize(size int) DEKManagerOption {
	return func(c *DEKManagerConfig) {
		c.MaxCacheSize = size
	}
}

func WithCacheExpiration(d time.Duration) DEKManagerOption {
	return func(c *DEKManagerConfig) {
		c.CacheExpiration = d
	}
}

func WithDriverName(driverName string) DEKManagerOption {
	return func(c *DEKManagerConfig) {
		c.DriverName = driverName
	}
}

func WithFunction(name string, fn DEKGenerationFunc) DEKManagerOption {
	return func(c *DEKManagerConfig) {
		if c.DEKGenFuncs == nil {
			c.DEKGenFuncs = make(map[string]DEKGenerationFunc)
		}
		c.DEKGenFuncs[name] = fn
	}
}

func WithDefaultGenFuncName(name string) DEKManagerOption {
	return func(c *DEKManagerConfig) {
		c.DefaultGenFuncName = name
	}
}

func WithMaxKeyFuncCache(size int) DEKManagerOption {
	return func(c *DEKManagerConfig) {
		c.MaxKeyFuncCache = size
	}
}

func NewDEKManager(db *sql.DB, mek []byte, options ...DEKManagerOption) (*DEKManager, error) {
	if len(mek) != 32 {
		return nil, fmt.Errorf("invalid MEK size: must be 32 bytes")
	}

	config := &DEKManagerConfig{
		DB:                    db,
		MEK:                   mek,
		SchemaName:            "public",
		TablePrefix:           "dek_store",
		DEKRotationPeriod:     90 * 24 * time.Hour,
		TransitionCheckPeriod: time.Hour,
		LockLeaseDuration:     3 * time.Minute,
		Logger:                newDefaultLogger(),
		MaxCacheSize:          1000,
		CacheExpiration:       24 * time.Hour,
		DriverName:            "pgx",
		DEKGenFuncs:           make(map[string]DEKGenerationFunc),
		DefaultGenFuncName:    "aes256-random",
		MaxKeyFuncCache:       1000,
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
		dekGenFuncs:           make(map[string]DEKGenerationFunc),
		defaultGenFuncName:    config.DefaultGenFuncName,
		keyFuncCache:          newKeyFuncCache(config.MaxKeyFuncCache),
	}

	// Add default DEK generation functions
	defaultFuncs := map[string]DEKGenerationFunc{
		"aes256-random": generateAES256RandomDEK,
		"aes192-random": generateAES192RandomDEK,
		"aes128-random": generateAES128RandomDEK,
	}

	for name, fn := range defaultFuncs {
		if _, exists := config.DEKGenFuncs[name]; !exists {
			config.DEKGenFuncs[name] = fn
		}
	}

	// Copy DEK generation functions to the manager
	for name, fn := range config.DEKGenFuncs {
		manager.dekGenFuncs[name] = fn
	}

	if err := manager.initializeDB(); err != nil {
		return nil, fmt.Errorf("failed to initialize database: %w", err)
	}

	if err := manager.initializeOrValidateMEK(); err != nil {
		return nil, fmt.Errorf("failed to initialize or validate MEK: %w", err)
	}

	manager.wg.Add(2)
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
	_, err = tx.ExecContext(ctx, fmt.Sprintf(createKeyInfoTableSQL, dm.schemaName, dm.tablePrefix))
	if err != nil {
		return fmt.Errorf("failed to create key_info table: %w", err)
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
		if dm.oldMEK != nil {
			var oldMEKID int
			err = tx.QueryRowContext(ctx, fmt.Sprintf(`
				SELECT id FROM "%s"."%s_mek"
				WHERE mek_hash = $1
			`, dm.schemaName, dm.tablePrefix), dm.hashMEK(dm.oldMEK)).Scan(&oldMEKID)
			if err != nil {
				return fmt.Errorf("failed to find old MEK: %w", err)
			}

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
				if err := dm.createNewMEKEntry(ctx, tx, mekHash); err != nil {
					return fmt.Errorf("failed to create new MEK entry: %w", err)
				}
			} else {
				return fmt.Errorf("old MEK is not the current MEK")
			}
		} else {
			var count int
			err = tx.QueryRowContext(ctx, fmt.Sprintf(`
				SELECT COUNT(*) FROM "%s"."%s_dek"
			`, dm.schemaName, dm.tablePrefix)).Scan(&count)
			if err != nil {
				return fmt.Errorf("failed to check existing DEKs: %w", err)
			}
			if count > 0 {
				return fmt.Errorf("provided MEK does not match existing encrypted DEKs")
			}

			if err := dm.createNewMEKEntry(ctx, tx, mekHash); err != nil {
				return fmt.Errorf("failed to create new MEK entry: %w", err)
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

type RegisterKeyOption func(*registerKeyOptions)

type registerKeyOptions struct {
	skipCache bool
}

func WithSkipCache() RegisterKeyOption {
	return func(opts *registerKeyOptions) {
		opts.skipCache = true
	}
}

func (dm *DEKManager) RegisterKey(ctx context.Context, keyName string, opts ...RegisterKeyOption) error {
	options := &registerKeyOptions{}
	for _, opt := range opts {
		opt(options)
	}

	if !options.skipCache {
		dm.keyFuncCache.mutex.RLock()
		_, exists := dm.keyFuncCache.items[keyName]
		dm.keyFuncCache.mutex.RUnlock()
		if exists {
			return nil // Key is already registered
		}
	}

	// Proceed with registration
	return dm.RegisterKeyWithFunction(ctx, keyName, dm.defaultGenFuncName)
}

func (dm *DEKManager) RegisterKeyWithFunction(ctx context.Context, keyName, genFuncName string) error {
	dm.dekGenMutex.RLock()
	_, exists := dm.dekGenFuncs[genFuncName]
	dm.dekGenMutex.RUnlock()

	if !exists {
		return fmt.Errorf("DEK generation function '%s' not registered", genFuncName)
	}

	tx, err := dm.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	var existingFuncName string
	err = tx.QueryRowContext(ctx, fmt.Sprintf(`
		SELECT gen_func_name FROM "%s"."%s_key_info"
		WHERE key_name = $1
	`, dm.schemaName, dm.tablePrefix), keyName).Scan(&existingFuncName)

	if err == nil {
		// Key already exists
		if existingFuncName != genFuncName {
			return fmt.Errorf("key '%s' already registered with a different function: %s", keyName, existingFuncName)
		}
		// Key exists with the same function, this is a successful idempotent operation
		dm.keyFuncCache.Add(keyName, genFuncName)
		return tx.Commit()
	} else if err != sql.ErrNoRows {
		return fmt.Errorf("failed to check existing key: %w", err)
	}

	// Key doesn't exist, insert new entry
	_, err = tx.ExecContext(ctx, fmt.Sprintf(`
		INSERT INTO "%s"."%s_key_info" (key_name, gen_func_name)
		VALUES ($1, $2)
	`, dm.schemaName, dm.tablePrefix), keyName, genFuncName)

	if err != nil {
		return fmt.Errorf("failed to register key: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	// Update the cache
	dm.keyFuncCache.Add(keyName, genFuncName)

	return nil
}

func (dm *DEKManager) GetDEK(ctx context.Context, keyName string) ([]byte, int, error) {
	if !dm.isCurrentMEK {
		dm.logger.Warn("Using an old version of MEK to retrieve DEK.", "key_name", keyName)
	}

	// Check DEK cache first
	if cachedDEK, cachedVersion, found := dm.getFromCache(keyName); found {
		return cachedDEK, cachedVersion, nil
	}

	// Check key-function cache
	genFuncName, found := dm.keyFuncCache.Get(keyName)
	if !found {
		var err error
		genFuncName, err = dm.getGenFuncNameFromDB(ctx, keyName)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to get generation function name: %w", err)
		}
		dm.keyFuncCache.Add(keyName, genFuncName)
	}

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
			return nil, 0, fmt.Errorf("cannot create new DEK with old MEK")
		}
		dek, newVersion, err := dm.generateAndStoreDEKWithinTx(ctx, tx, keyName, genFuncName)
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

	dm.addToCache(keyName, version, dek)

	return dek, version, nil
}

func (dm *DEKManager) getGenFuncNameFromDB(ctx context.Context, keyName string) (string, error) {
	var genFuncName string
	err := dm.db.QueryRowContext(ctx, fmt.Sprintf(`
		SELECT gen_func_name FROM "%s"."%s_key_info"
		WHERE key_name = $1
	`, dm.schemaName, dm.tablePrefix), keyName).Scan(&genFuncName)

	if err == sql.ErrNoRows {
		return "", fmt.Errorf("key '%s' not registered", keyName)
	} else if err != nil {
		return "", fmt.Errorf("failed to query key info: %w", err)
	}

	return genFuncName, nil
}

func (dm *DEKManager) generateAndStoreDEKWithinTx(ctx context.Context, tx *sql.Tx, keyName, genFuncName string) ([]byte, int, error) {
	dm.dekGenMutex.RLock()
	genFunc, exists := dm.dekGenFuncs[genFuncName]
	dm.dekGenMutex.RUnlock()

	if !exists {
		return nil, 0, fmt.Errorf("DEK generation function '%s' not registered", genFuncName)
	}

	dek, err := genFunc(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to generate DEK: %w", err)
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

func (dm *DEKManager) RotateDEK(ctx context.Context, keyName string) error {
	if !dm.isCurrentMEK {
		return fmt.Errorf("cannot rotate DEK with an old version of MEK")
	}

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
		return fmt.Errorf("failed to acquire lock for DEK rotation")
	}

	var rotationErr error
	defer func() {
		unlockErr := dm.releaseLock(ctx, tx, lockName)
		if unlockErr != nil {
			if rotationErr != nil {
				dm.logger.Warn("Failed to release lock after error", "error", unlockErr)
			} else {
				rotationErr = fmt.Errorf("failed to release lock: %w", unlockErr)
			}
		}

		if rotationErr == nil {
			if commitErr := tx.Commit(); commitErr != nil {
				rotationErr = fmt.Errorf("failed to commit transaction: %w", commitErr)
			}
		}
	}()

	var genFuncName string
	err = tx.QueryRowContext(ctx, fmt.Sprintf(`
		SELECT gen_func_name FROM "%s"."%s_key_info"
		WHERE key_name = $1
	`, dm.schemaName, dm.tablePrefix), keyName).Scan(&genFuncName)

	if err != nil {
		rotationErr = fmt.Errorf("failed to get generation function for key '%s': %w", keyName, err)
		return rotationErr
	}

	dek, version, err := dm.generateAndStoreDEKWithinTx(ctx, tx, keyName, genFuncName)
	if err != nil {
		rotationErr = fmt.Errorf("failed to generate and store new DEK: %w", err)
		return rotationErr
	}

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

func (dm *DEKManager) rotateAllDEKs() error {
	ctx := context.Background()
	tx, err := dm.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	rows, err := tx.QueryContext(ctx, fmt.Sprintf(`
		SELECT key_name, gen_func_name
		FROM "%s"."%s_key_info"
	`, dm.schemaName, dm.tablePrefix))
	if err != nil {
		return fmt.Errorf("failed to query existing keys: %w", err)
	}
	defer rows.Close()

	var keysToRotate []struct {
		keyName     string
		genFuncName string
	}

	for rows.Next() {
		var keyName, genFuncName string
		if err := rows.Scan(&keyName, &genFuncName); err != nil {
			return fmt.Errorf("failed to scan key info: %w", err)
		}
		keysToRotate = append(keysToRotate, struct {
			keyName     string
			genFuncName string
		}{keyName, genFuncName})
	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf("error iterating over key names: %w", err)
	}

	for _, key := range keysToRotate {
		dm.dekGenMutex.RLock()
		_, exists := dm.dekGenFuncs[key.genFuncName]
		dm.dekGenMutex.RUnlock()

		if !exists {
			err := fmt.Errorf("unregistered function for key during rotation")
			dm.logger.Warn("Rotation failed due to unregistered function",
				"key_name", key.keyName,
				"gen_func_name", key.genFuncName,
				"error", err)
			return err
		}

		if err := dm.rotateDEKWithinTx(ctx, tx, key.keyName, key.genFuncName); err != nil {
			dm.logger.Warn("Error rotating DEK",
				"key_name", key.keyName,
				"error", err)
			return fmt.Errorf("failed to rotate DEK for key '%s': %w", key.keyName, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

func (dm *DEKManager) rotateDEKWithinTx(ctx context.Context, tx *sql.Tx, keyName, genFuncName string) error {
	lockName := fmt.Sprintf("dek_rotation_%s", keyName)
	locked, err := dm.acquireLock(ctx, tx, lockName)
	if err != nil {
		return fmt.Errorf("failed to acquire lock: %w", err)
	}
	if !locked {
		return fmt.Errorf("failed to acquire lock for DEK rotation")
	}

	defer func() {
		if unlockErr := dm.releaseLock(ctx, tx, lockName); unlockErr != nil {
			dm.logger.Warn("Failed to release lock after rotation", "error", unlockErr)
		}
	}()

	dek, version, err := dm.generateAndStoreDEKWithinTx(ctx, tx, keyName, genFuncName)
	if err != nil {
		return fmt.Errorf("failed to generate and store new DEK: %w", err)
	}

	dm.addToCache(keyName, version, dek)
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

func (dm *DEKManager) RemoveKey(ctx context.Context, keyName string) error {
	tx, err := dm.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Remove from DEKs table
	_, err = tx.ExecContext(ctx, fmt.Sprintf(`
		DELETE FROM "%s"."%s_dek"
		WHERE key_name = $1
	`, dm.schemaName, dm.tablePrefix), keyName)
	if err != nil {
		return fmt.Errorf("failed to remove DEKs for key '%s': %w", keyName, err)
	}

	// Remove from key_info table
	result, err := tx.ExecContext(ctx, fmt.Sprintf(`
		DELETE FROM "%s"."%s_key_info"
		WHERE key_name = $1
	`, dm.schemaName, dm.tablePrefix), keyName)
	if err != nil {
		return fmt.Errorf("failed to remove key info for key '%s': %w", keyName, err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("key '%s' not found", keyName)
	}

	// Commit the transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	// Remove from DEK cache
	dm.removeFromCache(keyName)

	// Remove from key-function cache
	dm.keyFuncCache.Remove(keyName)

	dm.logger.Warn("Key removed successfully", "key_name", keyName)

	return nil
}

func (dm *DEKManager) removeFromCache(keyName string) {
	dm.cacheMutex.Lock()
	defer dm.cacheMutex.Unlock()
	delete(dm.caches, keyName)
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

	oldDEKs, err := dm.fetchOldDEKs(tx)
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("failed to fetch old DEKs: %w", err)
	}

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

	dek, err := dm.decryptDEKWithMEK(dm.oldMEK, oldEncryptedDEK)
	if err != nil {
		return fmt.Errorf("failed to decrypt old DEK: %w", err)
	}

	newEncryptedDEK, err := dm.encryptDEK(dek)
	if err != nil {
		return fmt.Errorf("failed to re-encrypt DEK: %w", err)
	}

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
			items:    make(map[int]*list.Element),
			list:     list.New(),
			capacity: dm.maxCacheSize,
		}
		dm.caches[keyName] = cache
	}

	if elem, exists := cache.items[version]; exists {
		cache.list.MoveToBack(elem)
		item := elem.Value.(*cacheItem)
		item.value = dek
		item.timestamp = time.Now()
	} else {
		if cache.list.Len() >= cache.capacity {
			oldest := cache.list.Front()
			if oldest != nil {
				oldestItem := oldest.Value.(*cacheItem)
				delete(cache.items, oldestItem.key)
				cache.list.Remove(oldest)
			}
		}
		item := &cacheItem{key: version, value: dek, timestamp: time.Now()}
		elem := cache.list.PushBack(item)
		cache.items[version] = elem
	}
}

func (dm *DEKManager) Shutdown() {
	dm.cancel()

	done := make(chan struct{})
	go func() {
		dm.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// All goroutines finished
	case <-time.After(20 * time.Second):
		dm.logger.Warn("Shutdown timed out after 20 seconds")
	}

	time.Sleep(2 * time.Second)
}

func (dm *DEKManager) SchemaName() string {
	return dm.schemaName
}

func (dm *DEKManager) TablePrefix() string {
	return dm.tablePrefix
}

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

func generateAES256RandomDEK(ctx context.Context) ([]byte, error) {
	return generateRandomDEK(32)
}

func generateAES192RandomDEK(ctx context.Context) ([]byte, error) {
	return generateRandomDEK(24)
}

func generateAES128RandomDEK(ctx context.Context) ([]byte, error) {
	return generateRandomDEK(16)
}

func generateRandomDEK(length int) ([]byte, error) {
	dek := make([]byte, length)
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return nil, fmt.Errorf("failed to generate random %d-bit AES key: %w", length*8, err)
	}
	return dek, nil
}

func (dm *DEKManager) GetDEKByVersion(ctx context.Context, keyName string, version int) ([]byte, error) {
	tx, err := dm.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	var encryptedDEK string
	var mekID int

	err = tx.QueryRowContext(ctx, fmt.Sprintf(`
		SELECT encrypted_dek, mek_id 
		FROM "%s"."%s_dek" 
		WHERE key_name = $1 AND version = $2 AND mek_id = $3
		LIMIT 1
	`, dm.schemaName, dm.tablePrefix), keyName, version, dm.currentMEKID).Scan(&encryptedDEK, &mekID)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("DEK not found for key %s and version %d with current MEK", keyName, version)
	} else if err != nil {
		return nil, fmt.Errorf("failed to query DEK: %w", err)
	}

	dek, err := dm.decryptDEK(encryptedDEK)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt DEK: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("failed to commit transaction: %w", err)
	}

	return dek, nil
}

func (dm *DEKManager) ListKeys(ctx context.Context) ([]string, error) {
	rows, err := dm.db.QueryContext(ctx, fmt.Sprintf(`
		SELECT key_name FROM "%s"."%s_key_info"
	`, dm.schemaName, dm.tablePrefix))
	if err != nil {
		return nil, fmt.Errorf("failed to query key names: %w", err)
	}
	defer rows.Close()

	var keys []string
	for rows.Next() {
		var keyName string
		if err := rows.Scan(&keyName); err != nil {
			return nil, fmt.Errorf("failed to scan key name: %w", err)
		}
		keys = append(keys, keyName)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating over key names: %w", err)
	}

	return keys, nil
}

func (dm *DEKManager) GetKeyInfo(ctx context.Context, keyName string) (string, int, error) {
	var genFuncName string
	var latestVersion int

	err := dm.db.QueryRowContext(ctx, fmt.Sprintf(`
		SELECT ki.gen_func_name, COALESCE(MAX(d.version), 0) as latest_version
		FROM "%s"."%s_key_info" ki
		LEFT JOIN "%s"."%s_dek" d ON ki.key_name = d.key_name
		WHERE ki.key_name = $1
		GROUP BY ki.gen_func_name
	`, dm.schemaName, dm.tablePrefix, dm.schemaName, dm.tablePrefix), keyName).Scan(&genFuncName, &latestVersion)

	if err == sql.ErrNoRows {
		return "", 0, fmt.Errorf("key '%s' not found", keyName)
	} else if err != nil {
		return "", 0, fmt.Errorf("failed to get key info: %w", err)
	}

	return genFuncName, latestVersion, nil
}
