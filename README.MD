# gopgdekmanager

⭐ If you find this project useful, please consider giving it a star on GitHub! ⭐

`gopgdekmanager` is a robust Go library for managing encryption keys in distributed environments using PostgreSQL. It provides a comprehensive system for handling Master Encryption Keys (MEKs) and Data Encryption Keys (DEKs), featuring automatic rotation, distributed locking, and recovery operations.

## Features

- **Master Encryption Key (MEK) Management**: Secure handling of MEKs, including rotation and recovery.
- **Data Encryption Key (DEK) Management**: Creation, retrieval, and rotation of DEKs for multiple named keys.
- **Symmetric DEKs**: Generates secure, symmetric DEKs of 32 bytes (256 bits) in length, suitable for use with AES-256 and other symmetric encryption algorithms.
- **Automatic DEK Rotation**: Configurable periodic rotation of DEKs.
- **Distributed Locking**: Prevents race conditions in distributed environments during key operations.
- **MEK Recovery**: Support for recovery using older MEKs in emergency scenarios.
- **Key Versioning**: Maintains versions of both MEKs and DEKs for traceability and backward compatibility.
- **PostgreSQL Backend**: Utilizes PostgreSQL for secure storage of encrypted keys.
- **Caching**: In-memory caching of DEKs for improved performance.
- **Configurable Cleanup**: Automatic cleanup of old, inactive keys after a configurable period.

## Installation

```bash
go get github.com/tzahifadida/go-pg-dek-manager
```

## Usage

### Initialization

```go
import (
    "database/sql"
    "github.com/tzahifadida/go-pg-dek-manager"
)

db, err := sql.Open("postgres", "your_connection_string")
if err != nil {
    // Handle error
}

mek := []byte("your-32-byte-master-encryption-key")

manager, err := gopgdekmanager.NewDEKManager(db, mek,
    gopgdekmanager.WithCleanupPeriod(180*24*time.Hour),
    gopgdekmanager.WithDEKRotationPeriod(30*24*time.Hour),
)
if err != nil {
    // Handle error
}
defer manager.Shutdown()
```

### Getting a DEK

```go
dek, version, err := manager.GetDEK("user_data")
if err != nil {
    // Handle error
}
// Use dek for encryption/decryption
// Note: dek is a 32-byte symmetric key suitable for AES-256
```

### Manual DEK Rotation

```go
err := manager.RotateDEK("user_data")
if err != nil {
    // Handle error
}
```

## Configuration Options

- `WithCleanupPeriod(d time.Duration)`: Set the period for cleaning up old DEKs.
- `WithDEKRotationPeriod(d time.Duration)`: Set the period for automatic DEK rotation.
- `WithTransitionCheckPeriod(d time.Duration)`: Set the period for checking MEK transitions.
- `WithTablePrefix(prefix string)`: Set a custom table prefix for database tables.
- `WithSchemaName(schema string)`: Set a custom schema name for database tables.
- `WithLogger(logger MinimalLogger)`: Provide a custom logger implementation.
- `WithLockLeaseDuration(d time.Duration)`: Set the duration for distributed locks.
- `WithOldMEK(oldMEK []byte)`: Provide an old MEK for transition scenarios.
- `WithMaxCacheSize(size int)`: Set the maximum size for the in-memory DEK cache.
- `WithCacheExpiration(d time.Duration)`: Set the expiration duration for cached DEKs.
- `WithDriverName(driverName string)`: Set the database driver name.

## MEK Handling

- Supports using older versions of MEKs with appropriate warnings.
- Allows DEK retrieval with old MEKs, but blocks rotation operations.
- Logs warnings when using an old MEK.

## Best Practices

1. **MEK Security**: Store the MEK securely outside of the database. Consider using a hardware security module (HSM) or secure key management service.
2. **Regular Rotation**: Implement a policy for regular MEK and DEK rotation.
3. **Monitoring**: Set up monitoring for key operations, especially failed attempts and recoveries.
4. **Backup**: Regularly backup your database, including the key tables.
5. **Access Control**: Implement strict access controls to the database and key management functions.

## Distributed Environment Considerations

- Uses distributed locking to prevent race conditions during key operations.
- Ensure all instances in your distributed system use the same database for consistency.
- Configure appropriate timeouts and retry mechanisms for distributed operations.

## Security Notes

- This library provides key management functionality but does not handle the actual encryption of your data. Use the DEKs retrieved from this library with standard encryption libraries for data encryption.
- The generated DEKs are 32 bytes (256 bits) long, making them suitable for use with AES-256 and other strong symmetric encryption algorithms.
- Always use TLS for database connections in production environments.
- Regularly audit and rotate all keys, including database credentials.

## Testing

The library includes a comprehensive test suite. To run the tests:

```bash
go test -v ./...
```

Note: The tests require Docker to be installed and running, as they use testcontainers-go to spin up a PostgreSQL instance.

## Contributing

Contributions to `gopgdekmanager` are welcome! Please submit pull requests with any enhancements, bug fixes, or documentation improvements.

## License

[MIT License](LICENSE)

## Support

For issues, questions, or contributions, please open an issue in the GitHub repository.