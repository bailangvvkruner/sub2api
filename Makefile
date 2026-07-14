.PHONY: build build-frontend build-rust test test-rust test-rust-integration test-frontend test-frontend-critical

FRONTEND_CRITICAL_VITEST := \
	src/views/auth/__tests__/LinuxDoCallbackView.spec.ts \
	src/views/auth/__tests__/WechatCallbackView.spec.ts \
	src/views/user/__tests__/PaymentView.spec.ts \
	src/views/user/__tests__/PaymentResultView.spec.ts \
	src/components/user/profile/__tests__/ProfileInfoCard.spec.ts \
	src/views/admin/__tests__/SettingsView.spec.ts

# 一键编译前后端
build: build-rust build-frontend

# 编译前端（需要已安装依赖）
build-frontend:
	@pnpm --dir frontend run build

# Build the PostgreSQL-only Rust migration target.
build-rust:
	@cargo build --manifest-path backend-rust/Cargo.toml --locked

# 运行测试（后端 + 前端）
test: test-rust test-frontend

test-rust:
	@cargo fmt --manifest-path backend-rust/Cargo.toml --all -- --check
	@cargo clippy --manifest-path backend-rust/Cargo.toml --all-targets --locked -- -D warnings
	@cargo test --manifest-path backend-rust/Cargo.toml --all-targets --locked

test-rust-integration:
	@cargo test --manifest-path backend-rust/Cargo.toml --test postgres_migrations --locked -- --ignored --nocapture
	@cargo test --manifest-path backend-rust/Cargo.toml --test billing_core --locked -- --ignored --test-threads=1 --nocapture
	@cargo test --manifest-path backend-rust/Cargo.toml --test bootstrap_runtime --locked bootstrap::tests::postgres_bootstrap_is_idempotent_and_skips_existing_users -- --ignored --test-threads=1 --nocapture
	@cargo test --manifest-path backend-rust/Cargo.toml --lib --locked postgres_ops_mutations_and_combined_request_list_are_live -- --ignored --test-threads=1 --nocapture
	@cargo test --manifest-path backend-rust/Cargo.toml --lib --locked postgres_cycle_expires_orders_cleans_auth_and_executes_usage_tasks -- --ignored --test-threads=1 --nocapture
	@cargo test --manifest-path backend-rust/Cargo.toml --lib --locked postgres_hold_idempotency_and_cancel_release_are_atomic -- --ignored --test-threads=1 --nocapture
	@cargo test --manifest-path backend-rust/Cargo.toml --lib --locked postgres_expired_output_cleanup_claim_is_durable -- --ignored --test-threads=1 --nocapture
	@cargo test --manifest-path backend-rust/Cargo.toml --lib --locked postgres_batch_updates_are_atomic_and_proxy_delete_skips_in_use_rows -- --ignored --test-threads=1 --nocapture
	@cargo test --manifest-path backend-rust/Cargo.toml --lib --locked postgres_group_overrides_quotas_and_flagged_hashes_are_durable -- --ignored --test-threads=1 --nocapture
	@cargo test --manifest-path backend-rust/Cargo.toml --lib --locked postgres_setting_writes_commit_before_cache_invalidation -- --ignored --test-threads=1 --nocapture
	@cargo test --manifest-path backend-rust/Cargo.toml --lib --locked postgres_operation_lock_and_restore_write_gate_are_cross_instance -- --ignored --test-threads=1 --nocapture
	@cargo test --manifest-path backend-rust/Cargo.toml --lib --locked postgres_scheduler_claim_recovery_and_result_writes_are_atomic -- --ignored --test-threads=1 --nocapture
	@cargo test --manifest-path backend-rust/Cargo.toml --lib --locked postgres_forced_refund_is_atomic_and_idempotent -- --ignored --test-threads=1 --nocapture
	@cargo test --manifest-path backend-rust/Cargo.toml --lib --locked postgres_provider_secret_round_trip_preserves_and_masks_credentials -- --ignored --test-threads=1 --nocapture
	@cargo test --manifest-path backend-rust/Cargo.toml --lib --locked postgres_error_rule_crud_applies_defaults_and_patch_semantics -- --ignored --test-threads=1 --nocapture
	@cargo test --manifest-path backend-rust/Cargo.toml --lib --locked postgres_ops_runtime_locks_aggregates_and_alerts_are_replica_safe -- --ignored --test-threads=1 --nocapture
	@cargo test --manifest-path backend-rust/Cargo.toml --lib --locked postgres_ops_runtime_rolls_up_channels_and_prunes_moderation_logs -- --ignored --test-threads=1 --nocapture
	@cargo test --manifest-path backend-rust/Cargo.toml --lib --locked postgres_auth_rate_limits_are_cross_replica_and_hash_only -- --ignored --test-threads=1 --nocapture
	@cargo test --manifest-path backend-rust/Cargo.toml --lib --locked postgres_authority_is_cross_replica_and_recovers_ready_billing -- --ignored --test-threads=1 --nocapture

test-frontend:
	@pnpm --dir frontend run lint:check
	@pnpm --dir frontend run typecheck
	@$(MAKE) test-frontend-critical

test-frontend-critical:
	@pnpm --dir frontend exec vitest run $(FRONTEND_CRITICAL_VITEST)
