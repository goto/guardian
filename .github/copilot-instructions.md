# Copilot Instructions for Guardian

## Project Overview

**Guardian** is an on-demand access management system for data resources. It's a gRPC/HTTP API server (written in Go) that manages:
- Multi-provider resource access (BigQuery, GCS, Alibaba Cloud, Grafana, Metabase, etc.)
- User appeals for resource access
- Configurable approval workflows
- Grant lifecycle (create, approve, extend, revoke, dormancy checks)

### High-Level Architecture

```
┌─ CLI Layer (cobra) ─────────────────────────────────┐
│  guardian server start/migrate, grant, appeal, etc. │
└──────────────────────────────────────────────────────┘
                           ↓
┌─ API Layer (gRPC + HTTP Gateway) ─────────────────┐
│  api/handler/v1beta1/ (auto-generated from protos) │
│  internal/server/ - middleware, interceptors        │
└────────────────────────────────────────────────────┘
                           ↓
┌─ Service/Business Logic Layer ────────────────────┐
│  core/{appeal,grant,policy,provider,resource}     │
│  Each domain has:                                  │
│  - service.go (main business logic)               │
│  - service_test.go (comprehensive tests)          │
│  - errors.go (domain-specific errors)             │
│  - mocks/* (auto-generated mockery interfaces)    │
└────────────────────────────────────────────────────┘
                           ↓
┌─ Storage Layer (GORM + PostgreSQL) ───────────────┐
│  internal/store/postgres/                         │
│  - *_repository.go files (one per domain entity)  │
│  - migrations/*.sql (schema)                      │
│  - utils.go (complex queries, filters)            │
│  - model/ (ORM models)                            │
└────────────────────────────────────────────────────┘
```

### Key Patterns

**Repository Pattern**: Each domain (grant, appeal, policy, etc.) has a repository with `List()`, `GetByID()`, `Create()`, `Update()`, `Delete()` operations, plus domain-specific methods. These live in `internal/store/postgres/*_repository.go`.

**Service Injection**: Services accept repository interfaces (not concrete types). Interfaces are defined at the top of each `core/*/service.go`. Example:
```go
type repository interface {
    BulkUpsert(context.Context, []*domain.Appeal) error
    Find(context.Context, *domain.ListAppealsFilter) ([]*domain.Appeal, error)
    // ... other methods
}
```

**Domain Models**: Core entities live in `domain/` as value types (e.g., `Appeal`, `Grant`, `Policy`). They're separate from ORM models in `internal/store/postgres/model/`.

**Filtering & Querying**: Complex filters use `domain.List*Filter` structs. Common patterns in `internal/store/postgres/utils.go`:
- `applyGrantsFilter()` - applies WHERE/HAVING clauses
- `applyGrantsJoins()` - builds JOIN statements  
- `generateLabelSummaries()` - extracts aggregated data with JSONB
- `applyLabelFilter()` - filters by JSONB label fields

**Mocking**: Interfaces are tagged with `//go:generate mockery --name=xyz --exported --with-expecter`. Run `make generate` to create mocks in the same package.

---

## Build, Test & Lint

### Setup
```sh
make setup
```
Installs Go tools (mockery, buf, golangci-lint, protoc plugins).

### Build
```sh
make build
# Outputs to: dist/guardian
```

### Testing

**All tests with race detector:**
```sh
make test
```

**Quick tests (skips long store/postgres tests):**
```sh
make test-short
```

**Single test file:**
```sh
go test ./core/appeal -v
```

**Single test function:**
```sh
go test ./core/appeal -run TestBulkInsert -v
```

**With coverage output:**
```sh
make coverage
# Opens HTML report
```

### Code Quality

**Lint checks:**
```sh
make lint
```
Uses golangci-lint. Config: `.golangci.yml` (if present, otherwise defaults).

**Format code:**
```sh
make format
```

**Vet code:**
```sh
make vet
```

**Tidy dependencies:**
```sh
make tidy
```

---

## Database & Migrations

**Migration location:** `internal/store/postgres/migrations/`

**Database setup:**
```sh
./guardian server migrate -c config.yaml
```

All migrations run automatically on server startup. Schema is embedded in binary via `//go:embed migrations/*.sql`.

**Common patterns when modifying schema:**
1. Create new `.sql` migration file (numbered: `0001_init.sql`, `0002_add_column.sql`, etc.)
2. Use standard PostgreSQL SQL
3. Run `./guardian server migrate` to apply
4. Update corresponding ORM models in `internal/store/postgres/model/`
5. Update repository methods if query logic changed

---

## Protocol Buffers

**Definition location:** `api/proto/gotocompany/guardian/v1beta1/` (auto-generated from external proton repo)

**Regenerate from proton:**
```sh
make proto
```

This pulls the latest `.proto` files from the `goto/proton` repository and generates:
- `api/handler/v1beta1/*pb.go` (message types)
- `api/handler/v1beta1/*pb.gw.go` (HTTP gateway)
- `api/handler/v1beta1/*_grpc.pb.go` (gRPC stubs)

**Important:** Do not manually edit `api/proto/**/*pb.go` files. They're always auto-generated.

---

## Key Conventions

### Error Handling
- Domain-specific errors defined in `core/{domain}/errors.go`
- Common error type: `var ErrXyzNotFound = errors.New("xyz not found")`
- Wrap errors with context: `fmt.Errorf("failed to create appeal: %w", err)`
- Use `errors.Is()` and `errors.As()` for comparison

### Naming
- **Repositories:** `*Repository` struct with methods (e.g., `type GrantRepository struct`)
- **Services:** `*Service` struct (e.g., `type AppealService struct`)
- **Filters:** `domain.List*Filter` (e.g., `domain.ListAppealsFilter`)
- **Results:** `domain.*Result` (e.g., `domain.SummaryResult`)

### Testing
- Test files in same package: `*_test.go`
- Table-driven tests preferred for multiple scenarios
- Use `t.Run()` for subtests
- Mock interfaces auto-generated with mockery

### Complex Queries

When building queries with filters (especially GORM):
1. Start with base query: `db.WithContext(ctx)`
2. Apply joins: `applyGrantsJoins(db)`
3. Apply all WHERE conditions: `applyGrantsFilter(db, filter)`
4. Execute final query with preloads

**Important:** Do NOT call `.Table()` after filter/join setup—it resets the query context and loses WHERE conditions. This is a common bug.

### JSONB/Label Handling
Labels are stored as JSONB in PostgreSQL. Key patterns:
- Extract values: `JSONB_EACH(column)` 
- Check existence: `column IS NOT NULL` AND `column <> '{}'::jsonb`
- Filter by keys: `applyLabelFilter()` and `applyLabelKeyFilter()` in utils.go

---

## Common Tasks

### Adding a New Domain Entity

1. Define model in `domain/{entity}.go` with necessary fields
2. Create ORM model in `internal/store/postgres/model/{entity}.go`
3. Create repository in `internal/store/postgres/{entity}_repository.go`
4. Create service in `core/{entity}/service.go` (with repository interface)
5. Add repository tests in `internal/store/postgres/{entity}_repository_test.go`
6. Add service tests in `core/{entity}/service_test.go`
7. Update `internal/store/postgres/store.go` to include new repository

### Modifying a Query Filter

Most filtering logic lives in `internal/store/postgres/utils.go`:
- `applyGrantsFilter()` - add new WHERE clauses here for grant queries
- `applyAppealFilter()` - same for appeals
- Test in corresponding `*_repository_test.go` files

### Adding a New Provider

New providers go in `plugins/providers/{provider_name}/`:
```
plugins/providers/my_provider/
├── client.go          # API client for the provider
├── client_test.go
├── grant.go           # Grant-specific logic
├── resource.go        # Resource-specific logic
└── config.go          # Configuration schema
```

---

## Project Structure Reference

```
core/           - Business logic services (appeal, grant, policy, provider, resource, etc.)
cli/            - Command-line interface (Cobra-based)
api/            - Protocol buffer definitions & auto-generated handlers
internal/
  server/       - HTTP/gRPC server setup, middleware
  store/        - Database abstraction layer
    postgres/   - PostgreSQL implementation (repositories, migrations, models)
domain/         - Core domain models (not ORM models)
plugins/
  providers/    - Provider implementations (BigQuery, GCS, etc.)
  identities/   - Identity provider implementations (Shield, HTTP, etc.)
  notifiers/    - Notification implementations (Slack, Lark, etc.)
pkg/            - Reusable utilities (auth, crypto, evaluator, http, log, etc.)
```

---

## Dependencies

- **GORM** - ORM for PostgreSQL
- **Cobra** - CLI framework
- **protobuf/gRPC** - RPC framework
- **grpc-gateway** - HTTP->gRPC bridge
- **OpenTelemetry** - Observability (tracing, metrics)
- **sirupsen/logrus** - Structured logging

See `go.mod` for full dependency list. Use `go mod download` to fetch all.

---

## Running Locally

**Full setup:**
```sh
git clone git@github.com:goto/guardian.git
cd guardian
make setup
make build
cp internal/server/config.yaml config.yaml
# Edit config.yaml with your settings (DB, providers, etc.)
./guardian server migrate -c config.yaml
./guardian server start -c config.yaml
```

Then test via gRPC (gRPCurl) or HTTP (curl).
