//! `migrate` — apply the embedded migrations OUT-OF-BAND (the deploy-time step for a remote runtime).
//!
//! A remote runtime never migrates on startup (see `build_state`): Neon's pooled/PgBouncer endpoint
//! can't reliably hold sqlx's session advisory lock, and cold Lambdas would race. This bin runs the
//! migrations once, deliberately, against the DIRECT endpoint — point it there with
//! `MIGRATION_DATABASE_URL` (falls back to `DATABASE_URL` for local use). Exit code is non-zero on
//! failure so a CI deploy step gates on it.
//!
//! ```text
//! MIGRATION_DATABASE_URL=postgres://…direct-endpoint…/db  cargo run -p openom --bin migrate
//! ```

use std::process::ExitCode;

use sqlx::postgres::PgPoolOptions;

#[tokio::main]
async fn main() -> ExitCode {
    let url = std::env::var("MIGRATION_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .ok();
    let Some(url) = url else {
        eprintln!(
            "migrate: set MIGRATION_DATABASE_URL (the DIRECT Postgres endpoint) or DATABASE_URL"
        );
        return ExitCode::from(2);
    };

    // One connection, eager: fail fast and loud if the direct endpoint is unreachable.
    let pool = match PgPoolOptions::new().max_connections(1).connect(&url).await {
        Ok(pool) => pool,
        Err(err) => {
            eprintln!("migrate: cannot connect to the database: {err}");
            return ExitCode::FAILURE;
        }
    };

    match openom::run_migrations(&pool).await {
        Ok(()) => {
            println!("migrate: migrations applied.");
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("migrate: migration failed: {err}");
            ExitCode::FAILURE
        }
    }
}
