# Directory-Based Configuration Examples

This directory contains example configuration files for loading static clients and connectors from separate files instead of embedding them in the main configuration file.

## Overview

Instead of defining all clients and connectors in your main `config.yaml`, you can:
- Store each client in its own file in a directory
- Store each connector in its own file in a directory
- Manage configurations more easily in containerized environments without templating

## Directory Structure

```
/etc/dex/
├── config.yaml
├── clients/
│   ├── example-app.yaml
│   ├── mobile-app.yaml
│   └── admin-portal.yaml
└── connectors/
    ├── ldap.yaml
    ├── github.yaml
    └── google.yaml
```

## Main Configuration

In your main `config.yaml`, specify the directories:

```yaml
issuer: https://dex.example.com

storage:
  type: sqlite3
  config:
    file: /var/dex/dex.db

web:
  http: 0.0.0.0:5556

# Load clients from directory
staticClientsDir: /etc/dex/clients

# Load connectors from directory
connectorsDir: /etc/dex/connectors

# Optional: You can still define additional clients/connectors inline
staticClients:
  - id: legacy-client
    name: "Legacy Client"
    secret: "legacy-secret"
    redirectURIs:
      - "http://localhost:8080/callback"
```

## Client Files

Each client file should be named `<client-id>.yaml` or `<client-id>.yml`. The client ID is automatically derived from the filename.

**Example:** `clients/example-app.yaml`

```yaml
name: "Example Application"
redirectURIs:
  - "http://127.0.0.1:5555/callback"
secret: "ZXhhbXBsZS1hcHAtc2VjcmV0"
```

See the `clients/` directory for more examples.

## Connector Files

Each connector file should be named `<connector-id>.yaml` or `<connector-id>.yml`. The connector ID is automatically derived from the filename.

**Example:** `connectors/github.yaml`

```yaml
type: "github"
name: "GitHub"
config:
  clientID: "your-github-client-id"
  clientSecret: "your-github-client-secret"
```

See the `connectors/` directory for more examples.

## Important Notes

1. **Client/Connector ID**: The ID is taken from the filename (without the `.yaml` or `.yml` extension)
   - If an `id` field is present in the file, it must match the filename
   - Example: `my-app.yaml` will have ID `my-app`

2. **File Extensions**: Both `.yaml` and `.yml` extensions are supported
   - Other files (e.g., `.txt`, `.md`) are ignored
   - Subdirectories are ignored

3. **Merge Behavior**: Directory files are loaded first, then inline config entries
   - All IDs must be unique across both sources
   - Duplicate IDs will cause a startup error

4. **Environment Variables**: You can still use environment variable expansion
   - Use `secretEnv` instead of `secret` in client files
   - Use `clientSecretEnv` in connector configs
   - Ensure the feature flag is enabled if using environment expansion

5. **Missing Directory**: If the specified directory doesn't exist, a warning is logged and startup continues

## Benefits

- **No Templating Required**: Update configs without complex template engines
- **Easier Git Tracking**: Each client/connector is a separate file with clear diffs
- **Container-Friendly**: Mount individual files or directories as ConfigMaps/Secrets
- **Better Organization**: Separate files are easier to manage than one large config
- **Gradual Migration**: Mix directory-based and inline configs during transition

## Kubernetes Example

Mount client files from Secrets:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: dex-clients
type: Opaque
stringData:
  example-app.yaml: |
    name: "Example Application"
    redirectURIs:
      - "http://127.0.0.1:5555/callback"
    secret: "ZXhhbXBsZS1hcHAtc2VjcmV0"
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: dex
spec:
  template:
    spec:
      containers:
      - name: dex
        volumeMounts:
        - name: clients
          mountPath: /etc/dex/clients
      volumes:
      - name: clients
        secret:
          secretName: dex-clients
```

Then in your Dex config:
```yaml
staticClientsDir: /etc/dex/clients
```
