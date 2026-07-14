# Retired Backend Reference

This directory contains the retired pre-Rust implementation and historical
development assets. It is retained only for behavior comparison and migration
research. The Rust build does not read any source, migrations, or resources
from this directory.

Its Makefile, Dockerfile, and source packages are unsupported and must not be
used for production builds, tests, releases, installation, or deployment. The
only production backend is `backend-rust/`; PostgreSQL is its only required
state service.
