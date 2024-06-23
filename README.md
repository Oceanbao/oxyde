# Stockrs

Backend project for stocker app.

## Structure

`src/`

```bash
main.rs # entry point
common/ # common module
  errors.rs
  response.rs
users/
  model.rs
  repo.rs
stocks/
  model.rs
```

## Database by `Sqlx`

Workflow with `sqlx` using SQLite:

```bash
# Dev stage
###########
# Ensure ENV with DATABASE_URL set.
# (for production/build, set it as ?mode=rwc to auto-create the first time)
# Add code to init sqlite db if nonexist.
# (optional) Create database from sqlx CLI, reading from .env DATABASE_URL.
sqlx database create

# Iterate
#########
# Create migration schema.
sqlx migrate add NAME
# Run migration.
sqlx migrate run

# Iterate
#########
# Code with query! and changes.
# Prepare offline records.
cargo sqlx prepare
# Build project.
cargo build
# Commit repo.

# Build stage in Dockerfile.
############################
# Copy .sqlx files.
# Ensure sqlx-cli installed during build.
cargo sqlx prepare --check
cargo build
```
