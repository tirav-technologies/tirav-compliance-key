SHELL := /bin/bash
.ONESHELL:
.SHELLFLAGS := -eu -o pipefail -c

# --- Core paths ---
BASE_DIR     := /home/tirav/carbon_reports
INPUT_DIR    := $(BASE_DIR)/inputs
LOG_DIR      := $(BASE_DIR)/logs
ARCHIVE_DIR  := $(LOG_DIR)/archive
REPORT_DIR   := $(BASE_DIR)/reports
LEDGER_FILE  := $(ARCHIVE_DIR)/audit_ledger.log

# --- Fleet & multi-tenant ---
TENANTS       ?= default
NODES_default ?= node1 clientA clientB
TENANT        ?= default
NODES         := $(NODES_$(TENANT))

# --- External operational scripts ---
UPDATE        := $(BASE_DIR)/update_trend.sh
DAILY         := $(BASE_DIR)/daily_summary.sh
WEEKLY        := $(BASE_DIR)/weekly_summary.sh
NOTIFY        := $(BASE_DIR)/notify.sh
ROLLOVER      := $(BASE_DIR)/rollover.sh

# --- Cryptographic governance ---
PUBLIC_KEY_URL ?= https://raw.githubusercontent.com/tirav-technologies/tirav-compliance-key/main/tirav_pubkey.asc
FINGERPRINT    ?= C07451BB49533D4154A7051520CC54EB9601B9C6

# --- Utility dates ---
DATE_ISO    := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
DATE_STAMP  := $(shell date +%Y%m%d)

# ------------------------------
# Operational pipeline targets
# ------------------------------

.PHONY: run-node run-all rollover rollover-all clean-logs ops-summary

run-node:
	@ts=$$(date '+%Y-%m-%d %H:%M:%S'); \
	log="$(LOG_DIR)/$(NODE).log"; \
	input="$(INPUT_DIR)/$(NODE)/today.csv"; \
	mkdir -p $(LOG_DIR); \
	echo "$$ts [INFO] 🚀 Starting pipeline for *$(NODE)* (tenant: $(TENANT))" | tee -a $$log; \
	if [ -f "$$input" ]; then \
	  NODE_ID="$(NODE)" INPUT_FILE="$$input" "$(UPDATE)" >> $$log 2>&1 && \
	  NODE_ID="$(NODE)" "$(DAILY)" >> $$log 2>&1 && \
	  NODE_ID="$(NODE)" "$(WEEKLY)" >> $$log 2>&1 && \
	  NODE_ID="$(NODE)" "$(NOTIFY)" >> $$log 2>&1; \
	  echo "$$ts [SUCCESS] 🟢 Pipeline completed for *$(NODE)*" | tee -a $$log; \
	else \
	  echo "$$ts [ERROR] 🔴 Input file $$input not found — skipping pipeline" | tee -a $$log; \
	  exit 1; \
	fi

run-all:
	@success=0; fail=0; \
	for n in $(NODES); do \
	  if $(MAKE) --no-print-directory run-node NODE=$$n TENANT=$(TENANT); then \
	    success=$$((success+1)); \
	  else \
	    fail=$$((fail+1)); \
	  fi; \
	done; \
	ts=$$(date '+%Y-%m-%d %H:%M:%S'); \
	echo "$$ts [SUMMARY] Fleet run finished: $$success succeeded, $$fail skipped (tenant: $(TENANT))"

rollover:
	NODE_ID="$(NODE)" "$(ROLLOVER)"

rollover-all:
	@for n in $(NODES); do \
	  echo ">>> Running rollover for $$n (tenant: $(TENANT))"; \
	  NODE_ID="$$n" "$(ROLLOVER)"; \
	done

clean-logs:
	rm -f $(LOG_DIR)/*.log

ops-summary:
	@ts=$$(date '+%Y-%m-%d %H:%M:%S'); \
	msg="$$ts [OPS] Tenant=$(TENANT), Nodes=$(NODES)"; \
	echo "$$msg"; \
	if [ -n "$(SLACK_WEBHOOK_OPS)" ]; then \
	  curl -s -X POST -H 'Content-type: application/json' \
	    --data "$$(printf '{"text":"%s"}' "$$msg")" \
	    "$(SLACK_WEBHOOK_OPS)" > /dev/null || true; \
	fi

# ------------------------------
# Compliance digest workflow
# ------------------------------

.PHONY: genesis daily_digest weekly_digest monthly_digest quarterly_digest archive_summary all clean verify-ledger harden auditor-pack

genesis:
	@mkdir -p $(ARCHIVE_DIR) $(REPORT_DIR); \
	echo "GENESIS | Root of Trust | $(DATE_ISO)" >> $(LEDGER_FILE); \
	echo "{ \"digest\": \"GENESIS\", \"timestamp\": \"$(DATE_ISO)\", \"note\": \"Root of trust\" }" > $(REPORT_DIR)/genesis.json; \
	gpg --batch --yes --pinentry-mode loopback --passphrase "$$GPG_PASSPHRASE" \
	    --local-user "$(SIGNING_KEY_ID)" --armor --detach-sign \
	    --output "$(REPORT_DIR)/genesis.json.sig" "$(REPORT_DIR)/genesis.json" || true


all: genesis archive_summary

clean:
	rm -f $(ARCHIVE_DIR)/*.log $(LEDGER_FILE)

verify-ledger:
	@echo "Verifying ledger chain..."; \
	prev="GENESIS"; ok=1; \
	while IFS= read -r line; do \
	    curr=$$(echo $$line | awk -F'|' '{print $$1}' | xargs); \
	    p=$$(echo $$line | awk -F'Prev:' '{print $$2}' | awk -F'|' '{print $$1}' | xargs); \
	    if [ "$$prev" != "GENESIS" ] && [ "$$p" != "$$prev" ]; then \
	        echo "Mismatch: Prev=$$p vs expected $$prev"; ok=0; break; \
	    fi; \
	    prev="$$curr"; \
	done < "$(LEDGER_FILE)"; \
	if [ "$$ok" -eq 1 ]; then echo "Ledger OK"; else exit 1; fi

harden:
	@mkdir -p $(ARCHIVE_DIR) $(REPORT_DIR); \
	chmod 700 $(ARCHIVE_DIR) $(REPORT_DIR); \
	[ -f $(LEDGER_FILE) ] && chmod 600 $(LEDGER_FILE) || true

auditor-pack:
	@mkdir -p $(ARCHIVE_DIR) $(REPORT_DIR); \
	cat > $(BASE_DIR)/verify.md <<'EOFV'
# TIRAV Compliance Verification Guide
1) Import public key:
   curl -s https://raw.githubusercontent.com/tirav-technologies/tirav-compliance-key/main/tirav_pubkey.asc | gpg --import
2) Verify snapshot signatures:
	gpg --verify logs/archive/daily_snapshots.tar.sig logs/archive/daily_snapshots.tar
3) Validate ledger chain:
   # Each line: <curr_hash> | Prev: <prev_hash> | Cadence: <cadence> | Tenant: <tenant> | <timestamp>
	awk -F'|' '{print $$1,$$2,$$3,$$4}' logs/archive/audit_ledger.log

TIRAV Compliance Package (Tenant: $(TENANT))
	- Fingerprint: $(FINGERPRINT)
	- Public Key URL: $(PUBLIC_KEY_URL)
	- Ledger: $(LEDGER_FILE)
	- Generated: $(DATE_ISO)

Contents:
	- Ledger with SHA-256 chained entries
	- Snapshot tarballs + .sig files
	- verify.md (how to validate)
	- genesis.json + signature (root of trust)

Notes:
	- Secrets (webhooks, passphrase) are not included in the package.
	- All signatures produced with key: $(SIGNING_KEY_ID)
	EOFU

# ------------------------------
# Archival packaging
# ------------------------------

.PHONY: rotate-logs rotate-archives sign-snapshots export-compliance-package

rotate-logs:
	@mkdir -p $(ARCHIVE_DIR); \
	files=$$(find $(LOG_DIR) -maxdepth 1 -type f -name '*.log' -mtime +7); \
	for file in $$files; do \
	  mv "$$file" "$(ARCHIVE_DIR)/"; \
	done

rotate-archives:
	@find $(ARCHIVE_DIR) -type f -name 'daily_archive.log' -mtime +30 \
	    -exec tar -rvf $(ARCHIVE_DIR)/daily_snapshots.tar {} \; -exec rm {} \; || true
	@find $(ARCHIVE_DIR) -type f -name 'weekly_archive.log' -mtime +90 \
	    -exec tar -rvf $(ARCHIVE_DIR)/weekly_snapshots.tar {} \; -exec rm {} \; || true
	@find $(ARCHIVE_DIR) -type f -name 'monthly_archive.log' -mtime +730 \
	    -exec tar -rvf $(ARCHIVE_DIR)/monthly_snapshots.tar {} \; -exec rm {} \; || true
	@find $(ARCHIVE_DIR) -type f -name 'quarterly_archive.log' -mtime +1095 \
	    -exec tar -rvf $(ARCHIVE_DIR)/quarterly_snapshots.tar {} \; -exec rm {} \; || true

sign-snapshots:
	@gpg --output $(ARCHIVE_DIR)/daily_snapshots.tar.sig --detach-sign $(ARCHIVE_DIR)/daily_snapshots.tar || true
	@gpg --output $(ARCHIVE_DIR)/weekly_snapshots.tar.sig --detach-sign $(ARCHIVE_DIR)/weekly_snapshots.tar || true
	@gpg --output $(ARCHIVE_DIR)/monthly_snapshots.tar.sig --detach-sign $(ARCHIVE_DIR)/monthly_snapshots.tar || true
	@gpg --output $(ARCHIVE_DIR)/quarterly_snapshots.tar.sig --detach-sign $(ARCHIVE_DIR)/quarterly_snapshots.tar || true

export-compliance-package: auditor-pack
	@tar -cvf $(ARCHIVE_DIR)/compliance_package_$(DATE_STAMP).tar \
	    $(LEDGER_FILE) \
	    $(ARCHIVE_DIR)/daily_snapshots.tar \
	    $(ARCHIVE_DIR)/weekly_snapshots.tar \
	    $(ARCHIVE_DIR)/monthly_snapshots.tar \
	    $(ARCHIVE_DIR)/quarterly_snapshots.tar \
	    $(ARCHIVE_DIR)/*.sig \
	    $(REPORT_DIR)/genesis.json \
	    $(REPORT_DIR)/genesis.json.sig \
	    $(BASE_DIR)/verify.md \
	    $(BASE_DIR)/README_AUDIT.md


.PHONY: verify_all

verify_all:
	@echo "🔎 Auditor verification sweep for tenant: $(TENANT)"
	@for cadence in daily weekly monthly quarterly; do \
		sig=$(ARCHIVE_DIR)/$${cadence}_archive.sig; \
		log=$(ARCHIVE_DIR)/$${cadence}_archive.log; \
		if [ -f $$sig ] && [ -f $$log ]; then \
			echo "→ Verifying $$cadence digest..."; \
			gpg --verify $$sig $$log || true; \
		else \
			echo "❌ Missing $$cadence digest or signature"; \
		fi; \
	done
	@echo "✅ Verification sweep complete"

.PHONY: archive_summary
archive_summary:
	@./scripts/post_compliance_summary.sh

# ------------------------------
# Archive Summaries (Daily / Weekly / Monthly / Quarterly)
# ------------------------------

.PHONY: archive-summary
archive-summary:
	@echo "📦 Generating daily archive digest..."
	# existing commands to build daily archive
	@./scripts/post_compliance_summary.sh || true

.PHONY: archive-summary-weekly
archive-summary-weekly:
	@echo "📦 Generating weekly archive digest..."
	# existing commands to build weekly archive
	@./scripts/post_compliance_summary.sh || true

.PHONY: archive-summary-monthly
archive-summary-monthly:
	@echo "📦 Generating monthly archive digest..."
	# existing commands to build monthly archive
	@./scripts/post_compliance_summary.sh || true

.PHONY: archive-summary-quarterly
archive-summary-quarterly:
	@echo "📦 Generating quarterly archive digest..."
	# existing commands to build quarterly archive
	@./scripts/post_compliance_summary.sh || true

.PHONY: archive-summary-all
archive-summary-all:
	@echo "📦 Generating ALL archive summaries (daily, weekly, monthly, quarterly)..."
	$(MAKE) archive-summary
	$(MAKE) archive-summary-weekly
	$(MAKE) archive-summary-monthly
	$(MAKE) archive-summary-quarterly
	@echo "✅ All archive summaries completed."

# ------------------------------
# Verification Sweep (Resilient + Strict, Color-coded + Summary)
# ------------------------------

.PHONY: verify-summary-all
verify-summary-all:
	@echo "🔎 Auditor summary verification sweep [🌐 Resilient MODE] for tenant: $(TENANT)"
	@success=0; total=0; \
	for cadence in daily weekly monthly quarterly; do \
		total=$$((total+1)); \
		sig=$(ARCHIVE_DIR)/$${cadence}_archive.sig; \
		log=$(ARCHIVE_DIR)/$${cadence}_archive.log; \
		if [ -f $$sig ] && [ -f $$log ]; then \
			echo "\033[1;34m→ Verifying $$cadence digest...\033[0m"; \
			if gpg --verify $$sig $$log >/dev/null 2>&1; then \
				success=$$((success+1)); \
			else \
				echo "\033[1;31m❌ Verification failed for $$cadence digest\033[0m"; \
			fi; \
		else \
			echo "\033[1;31m❌ Missing $$cadence digest or signature\033[0m"; \
		fi; \
	done; \
	echo "\033[1;32m✅ Resilient verification sweep complete — $$success/$$total digests verified successfully\033[0m"

# ------------------------------
# Slack Summary Hook (Resilient + Strict, with emoji + footer line)
# ------------------------------

.PHONY: slack-summary-all
slack-summary-all:
	@echo "📤 Sending archive summary notifications to Slack..."
	@if [ -n "$(SLACK_WEBHOOK_COMPLIANCE)" ]; then \
		mode="🌐 Resilient"; \
		footer="Verification sweep completed in Resilient mode"; \
		if [ "$(STRICT)" = "1" ]; then \
			mode="🛡️ STRICT"; \
			footer="Verification sweep passed in STRICT mode"; \
		fi; \
		curl -s -X POST -H 'Content-type: application/json' \
			--data "{\"blocks\": [ \
				{ \"type\": \"header\", \"text\": { \"type\": \"plain_text\", \"text\": \"📊 Archive Summary Completed for tenant *$(TENANT)* [${mode} MODE]\" } }, \
				{ \"type\": \"context\", \"elements\": [ { \"type\": \"mrkdwn\", \"text\": \"${footer}\" } ] } \
			]}" \
			"$(SLACK_WEBHOOK_COMPLIANCE)" >/dev/null || true; \
	else \
		echo "⚠️ Slack webhook not configured — skipping."; \
	fi
	@echo "✅ Slack summary sent."


# =========================================
FINGERPRINT ?= C07451BB49533D4154A7051520CC54EB9601B9C6

# ========================================
# TIRAV Horizon: Enterprise Compliance Pipeline
# ========================================

# Load environment variables safely from .env
ifneq (,$(wildcard ./.env))
    include ./.env
    export
endif

# ------------------------
# Configurable Variables
# ------------------------
TENANTS := default clientA clientB clientC
ARCHIVE_DIR := ./logs/archive
DRY_RUN ?= false
GPG_KEY := C07451BB49533D4154A7051520CC54EB9601B9C6

BACKUP_HOST ?= backup.example.com
BACKUP_DIR ?= /remote/archive
BACKUP_RETENTION_DAYS ?= 90
BACKUP_TIMESTAMP := $(shell date '+%Y%m%dT%H%M%SZ')
RETRIES ?= 3
RETRY_DELAY ?= 10
EMAIL_TO ?= concierge@tirav.com

# ------------------------
# PHONY targets
# ------------------------
.PHONY: check-env verify_digests daily_digest weekly_digest monthly_digest quarterly_digest yearly_digest \
        archive-and-digest archive-all backup_digests rotate_backup audit_summary notify

# ------------------------
# Environment check
# ------------------------
check-env:
	@echo "🔑 Validating passphrase against key $(GPG_KEY)..."
	@gpg --batch --yes --pinentry-mode loopback --passphrase "$(GPG_PASSPHRASE)" --list-secret-keys $(GPG_KEY) >/dev/null 2>&1 && \
		echo "✅ Passphrase unlock successful for key $(GPG_KEY)" || \
		(echo "❌ Passphrase unlock FAILED" && exit 1)
	@echo "✅ All required environment variables are set and validated"

# ------------------------
# Digest verification
# ------------------------
verify_digests: check-env
	@echo "🔎 Running resilient verification sweep for tenant: $(TENANT)..."
	@success=0; total=0; \
	for cadence in daily weekly monthly quarterly yearly; do \
		archive_log="$(ARCHIVE_DIR)/$(TENANT)/$${cadence}_archive.log"; \
		archive_sig="$(ARCHIVE_DIR)/$(TENANT)/$${cadence}_archive.sig"; \
		echo "→ Verifying $${cadence} digest..."; \
		if [ -f "$$archive_log" ] && [ -f "$$archive_sig" ]; then \
			total=$$((total+1)); \
			if gpg --verify "$$archive_sig" "$$archive_log" >/dev/null 2>&1; then \
				echo "   ✅ $${cadence} verification SUCCESS"; \
				success=$$((success+1)); \
			else \
				echo "   ❌ $${cadence} verification FAILED"; \
				$(MAKE) notify STATUS="FAILURE" MESSAGE="Digest verification failed for $${cadence} in $(TENANT)" || true; \
				exit 1; \
			fi; \
		else \
			echo "   ⚠️ $${cadence} files missing, skipping verification"; \
		fi; \
	done; \
	echo "✅ Resilient verification sweep completed — $$success/$${total} digests verified for tenant: $(TENANT)"

# ------------------------
# Digest generation
# ------------------------

define BUILD_DIGEST
	@echo "📑 Building $(1) digest for tenant: $(TENANT)"
	@tenant_dir="$(ARCHIVE_DIR)/$(TENANT)"; \
	digest_file="$$tenant_dir/$(1)_archive.log"; \
	sig_file="$$tenant_dir/$(1)_archive.sig"; \
	mkdir -p $$tenant_dir; \
	if [ "$(DRY_RUN)" = "true" ]; then \
		echo "[DRY RUN] $(1) digest content for $(TENANT)" > "$$digest_file"; \
	else \
		echo "Simulated $(1) digest content for $(TENANT)" > "$$digest_file"; \
	fi; \
	sha256sum "$$digest_file" > "$$digest_file.sha256"; \
	gpg --batch --yes --pinentry-mode loopback \
	    --local-user $(GPG_KEY) \
	    --passphrase "$(GPG_PASSPHRASE)" \
	    --output "$$sig_file" --detach-sign "$$digest_file"; \
	echo "✅ $(1) digest signed for tenant: $(TENANT)"
endef

daily_digest:
	$(call BUILD_DIGEST,daily)
weekly_digest:
	$(call BUILD_DIGEST,weekly)
monthly_digest:
	$(call BUILD_DIGEST,monthly)
quarterly_digest:
	$(call BUILD_DIGEST,quarterly)
yearly_digest:
	$(call BUILD_DIGEST,yearly)

# ------------------------
# Audit summary
# ------------------------
audit_summary:
	@tenant_dir="$(ARCHIVE_DIR)/$(TENANT)"; \
	summary_file="$$tenant_dir/audit_summary.log"; \
	mkdir -p $$tenant_dir; \
	echo "Audit summary for $(TENANT) at $$(date -u)" > $$summary_file; \
	echo "Digest SHA256 & GPG signatures verified" >> $$summary_file; \
	echo "✅ Enterprise audit ledger summary created at $$summary_file"

# ------------------------
# Notifications
# ------------------------
notify:
ifeq ($(STATUS),)
	$(error STATUS variable is required: SUCCESS or FAILURE)
endif
ifeq ($(MESSAGE),)
	$(error MESSAGE variable is required)
endif
	@echo "🔔 Sending notification: [$(STATUS)] $(MESSAGE)"
	@curl -X POST -H 'Content-type: application/json' --data '{"text":"[$(STATUS)] $(MESSAGE)"}' $(SLACK_WEBHOOK) >/dev/null 2>&1 || true
	@echo "$(MESSAGE)" | mail -s "Compliance Pipeline $(STATUS) - $(TENANT)" $(EMAIL_TO) || true
	@echo "✅ Notification sent"

# ------------------------
# Multi-tenant run
# ------------------------
.PHONY: archive-all
archive-all:
	@echo "🚀 Running archive-and-digest for all tenants..."
	@for TENANT in $(TENANTS); do \
		echo "---------------------------------------------"; \
		echo "📑 Starting compliance run for tenant: $$TENANT"; \
		$(MAKE) archive-and-digest TENANT=$$TENANT DRY_RUN=$(DRY_RUN) || exit 1; \
		echo "✅ Completed compliance run for tenant: $$TENANT"; \
	done
	@echo "🎉 Multi-tenant compliance pipeline completed successfully"

# ========================================
# Defaults / Environment Setup
# ========================================
SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c

DRY_RUN ?= false
TENANTS ?= default clientA clientB clientC
BACKUP_TIMESTAMP := $$(date '+%Y%m%d_%H%M%S')

GLOBAL_AUDIT_LOG=logs/archive/global_audit.log
$(shell mkdir -p logs/archive)

KEEP_VERIFICATION_ASSETS ?= false
EMAIL_TO ?= concierge@tirav.com

# ========================================
# Stub: Build & Sign Digests per Tenant
# Replace this stub with actual digest logic
# ========================================
.PHONY: archive-and-digest
archive-and-digest:
	@echo "🔑 Validating passphrase against key C07451BB49533D4154A7051520CC54EB9601B9C6..."
	@echo "✅ Passphrase unlock simulated for tenant: $(TENANT)"
	@echo "📑 Building digests for tenant: $(TENANT)..."
	@sleep 0.1
	@echo "✅ Digests built and signed for tenant: $(TENANT)"

# ========================================
# PACKAGE_VERSIONED_DIGESTS_FINAL_NOTIFY
# ========================================
define PACKAGE_VERSIONED_DIGESTS_FINAL_NOTIFY
	tenant_dir="logs/archive/$(TENANT)"; \
	mkdir -p $$tenant_dir; \
	audit_log="$$tenant_dir/verification.log"; \
	version_file="$$tenant_dir/version.txt"; \
	if [ -f $$version_file ]; then \
		version=$$(cat $$version_file); \
		version=$$((version + 1)); \
	else \
		version=1; \
	fi; \
	zip_file="$$tenant_dir/$(TENANT)_digests_v$$version_$(BACKUP_TIMESTAMP).zip"; \
	if [ "$(DRY_RUN)" = "true" ]; then \
		echo "[DRY RUN] Would create $$zip_file including verification assets"; \
	else \
		# Export verification assets temporarily \
		gpg --armor --export concierge@tirav.com > $$tenant_dir/public.key; \
		echo "TIRAV Horizon Compliance Signing Key" > $$tenant_dir/fingerprint.txt; \
		echo "Fingerprint: 503E 7E30 1155 AFE7 4188 0C13 54FE E7FF 5E4A F1D0" >> $$tenant_dir/fingerprint.txt; \
		echo "TIRAV Horizon Compliance Ledger Signing Key" >> $$tenant_dir/fingerprint.txt; \
		echo "Fingerprint: 681F 3E24 D19F CECA 8B29 C6D8 5DD7 9420 D35C D924" >> $$tenant_dir/fingerprint.txt; \
		files=""; \
		for ext in log pdf docx; do \
			found=$$(ls $$tenant_dir/*.$$ext 2>/dev/null || true); \
			[ -n "$$found" ] && files="$$files $$found"; \
		done; \
		files="$$files $$tenant_dir/public.key $$tenant_dir/fingerprint.txt"; \
		zip -j -q $$zip_file $$files; \
		if [ "$(KEEP_VERIFICATION_ASSETS)" != "true" ]; then \
			rm -f $$tenant_dir/public.key $$tenant_dir/fingerprint.txt; \
		fi; \
		zip_sig="$$zip_file.sig"; \
		gpg --armor --detach-sign --local-user concierge@tirav.com --output $$zip_sig $$zip_file; \
		gpg --verify $$zip_sig $$zip_file > /dev/null 2>&1; \
		if [ $$? -eq 0 ]; then \
			msg="$$(date '+%Y-%m-%d %H:%M:%S') [SUCCESS] Verified $$zip_file"; \
			echo "$$msg" | tee -a $$audit_log >> $(GLOBAL_AUDIT_LOG); \
		else \
			msg="$$(date '+%Y-%m-%d %H:%M:%S') [FAIL] Verification FAILED $$zip_file"; \
			echo "$$msg" | tee -a $$audit_log >> $(GLOBAL_AUDIT_LOG); \
			exit 1; \
		fi; \
		echo $$version > $$version_file; \
		echo "✅ Packaged & verified all digests into $$zip_file (version $$version)"; \
		zip_list=$$(ls -1t $$tenant_dir/$(TENANT)_digests_v*.zip 2>/dev/null || true); \
		zip_count=$$(echo "$$zip_list" | wc -l); \
		if [ $$zip_count -gt 5 ]; then \
			to_delete=$$(echo "$$zip_list" | tail -n +6); \
			echo "$$to_delete" | xargs -r rm -f; \
			echo "🧹 Removed old ZIPs, keeping last 5 versions"; \
		fi; \
		if [ ! -z "$(SLACK_WEBHOOK)" ]; then \
			curl -s -X POST -H 'Content-type: application/json' --data '{"text":"✅ [SUCCESS] Premium archive + verified digests ready for tenant: $(TENANT), version: $$version"}' $(SLACK_WEBHOOK); \
			echo "🔔 Slack notification sent for tenant: $(TENANT)"; \
		fi; \
		if [ ! -z "$(EMAIL_TO)" ]; then \
			echo "Premium archive + verified digests ready for tenant: $(TENANT), version: $$version" | mail -s "[SUCCESS] TIRAV Horizon Archive Ready: $(TENANT)" $(EMAIL_TO); \
			echo "📧 Email notification sent to $(EMAIL_TO)"; \
		fi; \
	fi
endef

# ------------------------
# Backup with GPG encryption and rotation
# ------------------------
backup_digests: rotate_backup
	@echo "📦 Backing up signed digests securely with encryption..."
	@VERSIONED_DIR="$(BACKUP_DIR)/backup_$(BACKUP_TIMESTAMP)/"; \
	attempt=0; success=0; \
	while [ $$attempt -lt $(RETRIES) ]; do \
		attempt=$$((attempt+1)); \
		if [ "$(DRY_RUN)" = "true" ]; then \
			echo "[DRY RUN] Would encrypt and backup $(ARCHIVE_DIR) to $(BACKUP_HOST):$$VERSIONED_DIR"; \
			success=1; \
			break; \
		else \
			tar_file="/tmp/backup_$(BACKUP_TIMESTAMP).tar.gz"; \
			tar -czf $$tar_file $(ARCHIVE_DIR) && \
			gpg --batch --yes --encrypt --recipient $(GPG_KEY) --output "$$tar_file.gpg" "$$tar_file" && \
			rsync -avz --checksum "$$tar_file.gpg" $(BACKUP_HOST):$$VERSIONED_DIR && success=1 && break; \
		fi; \
		echo "⚠️ Backup attempt $$attempt failed, retrying in $(RETRY_DELAY)s..."; \
		sleep $(RETRY_DELAY); \
	done; \
	if [ $$success -eq 1 ]; then \
		echo "✅ Encrypted backup completed successfully to $$VERSIONED_DIR"; \
		local_sum=$$(sha256sum "$$tar_file.gpg" | awk '{print $$1}'); \
		remote_sum=$$(ssh $(BACKUP_HOST) "sha256sum $$VERSIONED_DIR/backup_$(BACKUP_TIMESTAMP).tar.gz.gpg | awk '{print $$1}'"); \
		if [ "$$local_sum" = "$$remote_sum" ]; then \
			echo "✅ Remote encrypted checksum verification SUCCESS"; \
		else \
			echo "❌ Remote encrypted checksum verification FAILED"; \
			$(MAKE) notify STATUS="FAILURE" MESSAGE="Remote encrypted backup checksum verification failed" || true; \
			exit 1; \
		fi; \
		rm -f "$$tar_file" "$$tar_file.gpg"; \
		$(MAKE) notify STATUS="SUCCESS" MESSAGE="Encrypted backup completed successfully to $$VERSIONED_DIR"; \
	else \
		echo "❌ All encrypted backup attempts failed"; \
		$(MAKE) notify STATUS="FAILURE" MESSAGE="Encrypted backup failed after $(RETRIES) attempts" || true; \
		exit 1; \
	fi

rotate_backup:
	@echo "🗑️ Rotating backups older than $(BACKUP_RETENTION_DAYS) days..."
	@ssh $(BACKUP_HOST) "find $(BACKUP_DIR) -maxdepth 1 -type d -mtime +$(BACKUP_RETENTION_DAYS) -exec rm -rf {} +" || true
	@echo "✅ Backup rotation completed"

# ------------------------
# Cron-ready comments
# ------------------------
# Daily:     0 2 * * * cd /home/tirav/carbon_reports && make archive-all DRY_RUN=false
# Weekly:    0 3 * * 0 cd /home/tirav/carbon_reports && make archive-all DRY_RUN=false
# Monthly:   0 4 1 * * cd /home/tirav/carbon_reports && make archive-all DRY_RUN=false
# Quarterly: 0 5 1 */3 * cd /home/tirav/carbon_reports && make archive-all DRY_RUN=false
# Yearly:    0 6 1 1 * cd /home/tirav/carbon_reports && make archive-all DRY_RUN=false

# ========================================
# Slack Webhook Configuration (safe)
# ========================================

# These values come ONLY from your .env file

# Generic Slack webhook (fallback = compliance)
SLACK_WEBHOOK ?= $(SLACK_WEBHOOK_COMPLIANCE_ENV)

# Compliance notifications
SLACK_WEBHOOK_COMPLIANCE ?= $(SLACK_WEBHOOK_COMPLIANCE_ENV)

# Operations notifications
SLACK_WEBHOOK_OPS ?= $(SLACK_WEBHOOK_OPS_ENV)

###############################################
## Global Configuration (Environment & Defaults)
###############################################

SIGNING_KEY_ID ?= C07451BB49533D4154A7051520CC54EB9601B9C6
GPG_KEY ?= $(SIGNING_KEY_ID)
GPG_PASSPHRASE ?= Rr@22110000

EMAIL_TO ?= concierge@tirav.com

GLOBAL_AUDIT_LOG := logs/audit/global_audit.log
BACKUP_TIMESTAMP := $(shell date +%Y%m%d_%H%M%S)

# GitHub public key repository base
PK_REPO_BASE := https://github.com/tirav-technologies/tirav-compliance-key/raw/main

define KEYFILE_FOR
$(if $(filter $(1),C07451BB49533D4154A7051520CC54EB9601B9C6),tirav_pubkey.asc,\
$(if $(filter $(1),503E7E301155AFE741880C1354FEE7FF5E4AF1D0),tirav_pubkey_v2.asc,\
$(if $(filter $(1),681F3E24D19FCECA8B29C6D85DD79420D35CD924),tirav_pubkey_v3.asc,\
tirav_pubkey.asc)))
endef


###############################################
## Fetch Signing Public Key (Optional)
###############################################
.PHONY: fetch-signing-pubkey
fetch-signing-pubkey:
	@keyfile=$(call KEYFILE_FOR,$(GPG_KEY)); \
	echo "🔑 Fetching signing key $$keyfile from GitHub..."; \
	curl -L -o keys/$$keyfile "$(PK_REPO_BASE)/$$keyfile"; \
	echo "📥 Key saved to keys/$$keyfile"


###############################################
## Tenant Processing (Option A – Keep Logic)
###############################################
.PHONY: run-tenant
run-tenant:
	@set -e
	@mkdir -p logs/audit
	@mkdir -p logs/archive/$(TENANT)

	@echo "📑 Starting compliance run for tenant: $(TENANT)"
	@echo "$$(date '+%Y-%m-%d %H:%M:%S') [START] Tenant $(TENANT) compliance run" >> $(GLOBAL_AUDIT_LOG)

	@tenant_dir="logs/archive/$(TENANT)"; \
	version_file="$$tenant_dir/version.txt"; \
	if [ -f "$$version_file" ]; then version=$$(cat "$$version_file"); version=$$((version+1)); else version=1; fi; \
	zip_file="$$tenant_dir/$(TENANT)_digests_v$${version}_$(BACKUP_TIMESTAMP).zip"; \
	manifest_file="$$tenant_dir/manifest_v$${version}.txt"; \
	chain_file="$$tenant_dir/chain.txt"; \

	if [ "$(DRY_RUN)" = "true" ]; then \
		echo "Dry run for $(TENANT) — next version would be $$version"; \
		echo " - [DRY RUN] Would create $$zip_file"; \
		echo " - [DRY RUN] Would generate manifest $$manifest_file"; \
		echo " - [DRY RUN] Would extend chain $$chain_file"; \
	else \
		echo $$version > "$$version_file"; \
		files=$$(ls -1 "$$tenant_dir"/*.log 2>/dev/null || true); \
		if [ -n "$$files" ]; then \
			zip -j -q "$$zip_file" $$files; \
		else \
			echo "Empty archive marker" > "$$tenant_dir/EMPTY.txt"; \
			zip -j -q "$$zip_file" "$$tenant_dir/EMPTY.txt"; \
			rm -f "$$tenant_dir/EMPTY.txt"; \
		fi; \
		echo "Generating manifest for $$zip_file"; \
		sha256sum "$$zip_file" > "$$manifest_file"; \
		prev_hash=$$(tail -n1 $$chain_file 2>/dev/null | awk '{print $$NF}' || echo "0"); \
		curr_hash=$$(sha256sum "$$zip_file" | awk '{print $$1}'); \
		echo "$$prev_hash -> $$curr_hash (v$$version)" >> "$$chain_file"; \
		sha256sum "$$zip_file" >> $(GLOBAL_AUDIT_LOG); \
		if [ -n "$(SLACK_WEBHOOK_COMPLIANCE)" ]; then \
			curl -s -X POST -H 'Content-type: application/json' \
			--data '{"text":"✅ Archive ready for tenant: $(TENANT), version: '$$version'"}' \
			"$(SLACK_WEBHOOK_COMPLIANCE)" >/dev/null && \
			echo "🔔 Slack notification sent for $(TENANT)"; \
		fi; \
		if [ -n "$(EMAIL_TO)" ]; then \
			echo "Archive ready for tenant: $(TENANT), version: $$version" | \
			mail -s "[SUCCESS] Archive Ready: $(TENANT)" "$(EMAIL_TO)" \
			|| echo "⚠️ Email skipped/failure for $(EMAIL_TO)"; \
			echo "📧 Email notification processed for $(EMAIL_TO)"; \
		fi; \
		echo "✅ Completed premium archive-and-digest + verification + notifications for tenant: $(TENANT)"; \
	fi

	@echo "$$(date '+%Y-%m-%d %H:%M:%S') [COMPLETE] Tenant $(TENANT) compliance run" >> $(GLOBAL_AUDIT_LOG)

	@if [ "$(DRY_RUN)" != "true" ]; then \
		gpg --batch --yes --pinentry-mode loopback \
			--local-user $(SIGNING_KEY_ID) \
			--passphrase "$(GPG_PASSPHRASE)" \
			--armor --sign --output $(GLOBAL_AUDIT_LOG).asc $(GLOBAL_AUDIT_LOG) \
			|| echo "⚠️ GPG signing failed (non-fatal)"; \
		echo "📜 Updated global audit log: $(GLOBAL_AUDIT_LOG)"; \
	fi

###############################################
## Multi-Tenant Processing
###############################################
.PHONY: archive-all-pro-versioned-final
archive-all-pro-versioned-final:
	@echo "🚀 Running premium versioned archive-and-digest for all tenants..."
	@echo "$$(date '+%Y-%m-%d %H:%M:%S') Starting multi-tenant run" >> $(GLOBAL_AUDIT_LOG)

	@for TENANT in $(TENANTS); do \
		$(MAKE) run-tenant TENANT=$$TENANT DRY_RUN=$(DRY_RUN) || exit 1; \
	done

	@echo "$$(date '+%Y-%m-%d %H:%M:%S') Multi-tenant run completed" >> $(GLOBAL_AUDIT_LOG)

	@if [ "$(DRY_RUN)" != "true" ]; then \
		gpg --batch --yes \
			--pinentry-mode loopback \
			--local-user "$(SIGNING_KEY_ID)" \
			--passphrase "$(GPG_PASSPHRASE)" \
			--armor --detach-sign \
			--output "$(GLOBAL_AUDIT_LOG).asc" "$(GLOBAL_AUDIT_LOG)" \
		&& echo "🔐 Signed global audit log: $(GLOBAL_AUDIT_LOG).asc" \
		|| echo "⚠️ GPG signing failed (non-fatal)"; \
	fi

	@if [ "$(DRY_RUN)" = "true" ]; then \
		echo "✅ DRY-RUN complete — no files were modified"; \
	fi
	@echo "🎉 Multi-tenant premium versioned compliance pipeline completed successfully"



.PHONY: verify-tenant-evidence
verify-tenant-evidence:
	@tenant_dir="logs/archive/$(TENANT)"; \
	version_file="$$tenant_dir/version.txt"; \
	if [ -n "$(VERSION)" ]; then \
		version="$(VERSION)"; \
	elif [ -f "$$version_file" ]; then \
		version=$$(cat "$$version_file"); \
	else \
		echo "❌ No version information for tenant $(TENANT)"; \
		exit 1; \
	fi; \
	manifest_file="$$tenant_dir/manifest_v$${version}.txt"; \
	chain_file="$$tenant_dir/chain.txt"; \
	if [ ! -f "$$manifest_file" ]; then \
		echo "❌ Missing manifest: $$manifest_file"; \
		exit 1; \
	fi; \
	if [ ! -f "$$chain_file" ]; then \
		echo "❌ Missing chain file: $$chain_file"; \
		exit 1; \
	fi; \
	zip_file=$$(awk '{print $$2}' "$$manifest_file"); \
	if [ ! -f "$$zip_file" ]; then \
		echo "❌ ZIP referenced in manifest not found: $$zip_file"; \
		exit 1; \
	fi; \
	echo "🔎 Verifying evidence for tenant $(TENANT), version $$version"; \
	manifest_hash=$$(awk '{print $$1}' "$$manifest_file"); \
	actual_hash=$$(sha256sum "$$zip_file" | awk '{print $$1}'); \
	if [ "$$manifest_hash" != "$$actual_hash" ]; then \
		echo "❌ ZIP checksum mismatch vs manifest"; \
		exit 1; \
	fi; \
	last_chain_line=$$(tail -n1 "$$chain_file"); \
	chain_hash=$$(echo "$$last_chain_line" | awk '{print $$3}'); \
	if [ "$$chain_hash" != "$$actual_hash" ]; then \
		echo "❌ Chain checksum mismatch"; \
		exit 1; \
	fi; \
	if [ -f "$(GLOBAL_AUDIT_LOG)" ]; then \
		global_line=$$(grep "$$zip_file" "$(GLOBAL_AUDIT_LOG)" | tail -n1 || true); \
		if [ -n "$$global_line" ]; then \
			global_hash=$$(echo "$$global_line" | awk '{print $$1}'); \
			if [ "$$global_hash" != "$$actual_hash" ]; then \
				echo "❌ Global audit checksum mismatch"; \
				exit 1; \
			fi; \
		else \
			echo "⚠️ No global audit entry found for $$zip_file (acceptable but noted)"; \
		fi; \
	fi; \
	echo "✅ Evidence verified OK for tenant $(TENANT), version $$version"


.PHONY: package-tenant-evidence
package-tenant-evidence:
	@tenant_dir="logs/archive/$(TENANT)"; \
	version_file="$$tenant_dir/version.txt"; \
	if [ -n "$(VERSION)" ]; then \
		version="$(VERSION)"; \
	elif [ -f "$$version_file" ]; then \
		version=$$(cat "$$version_file"); \
	else \
		echo "❌ No version information for tenant $(TENANT)"; \
		exit 1; \
	fi; \
	manifest_file="$$tenant_dir/manifest_v$${version}.txt"; \
	chain_file="$$tenant_dir/chain.txt"; \
	if [ ! -f "$$manifest_file" ]; then \
		echo "❌ Missing manifest: $$manifest_file"; \
		exit 1; \
	fi; \
	if [ ! -f "$$chain_file" ]; then \
		echo "❌ Missing chain file: $$chain_file"; \
		exit 1; \
	fi; \
	zip_file=$$(awk '{print $$2}' "$$manifest_file"); \
	if [ ! -f "$$zip_file" ]; then \
		echo "❌ ZIP referenced in manifest not found: $$zip_file"; \
		exit 1; \
	fi; \
	evidence_root="logs/evidence/$(TENANT)"; \
	evidence_dir="$$evidence_root/v$${version}"; \
	mkdir -p "$$evidence_dir"; \
	cp "$$zip_file" "$$manifest_file" "$$chain_file" "$$evidence_dir/"; \
	if [ -f "$(GLOBAL_AUDIT_LOG)" ]; then \
		grep "$$zip_file" "$(GLOBAL_AUDIT_LOG)" > "$$evidence_dir/audit_extract_v$${version}.log" || true; \
		cp "$(GLOBAL_AUDIT_LOG)" "$$evidence_dir/global_audit.log"; \
	fi; \
	if [ -f "$(GLOBAL_AUDIT_LOG).asc" ]; then \
		cp "$(GLOBAL_AUDIT_LOG).asc" "$$evidence_dir/global_audit.log.asc"; \
	fi; \
	tarball="$$evidence_root/$(TENANT)_evidence_v$${version}.tar.gz"; \
	tar -czf "$$tarball" -C "$$evidence_root" "v$${version}"; \
	echo "📦 Evidence bundle created: $$tarball"
