# Operation Index Backfill Tool

This tool safely backfills the correct `operation_index` values for existing deposit records that were stored with a hardcoded `operation_index = 0`.

## Problem Description

The Octo Protocol ingestion system previously hardcoded `operation_index = 0` for all deposits, regardless of their actual position within a Stellar transaction. This created a bug where multi-operation transactions had all their operations recorded with the same index, making it impossible to distinguish between them for on-chain verification purposes.

While the `uq_tx_horizon_op_id` constraint kept these records distinct (since each operation has a unique TOID), the `uq_tx_onchain` constraint on `(stellar_tx_hash, operation_index)` was effectively broken for multi-operation transactions.

## Solution Overview

This backfill tool:

1. **Decodes the real operation index** from the already-stored `horizon_op_id` (TOID) field
2. **Updates records in small batches** to avoid long table locks
3. **Maintains referential integrity** through careful transaction handling
4. **Is completely idempotent** - safe to run multiple times
5. **Validates constraint safety** before making any changes

## Database Constraint Analysis

### The Key Insight: Why Backfill is Safe

The critical question is: could backfilling ever violate the `uq_tx_onchain` partial unique index on `(stellar_tx_hash, operation_index)`?

**Answer: No, because the constraint violation is actually *fixed* by the backfill, not caused by it.**

#### Before Backfill
Consider a transaction with 3 operations, all currently stored incorrectly:
```
stellar_tx_hash    operation_index    horizon_op_id
"abc123"           0                  "67890-10-0"  <- correct
"abc123"           0                  "67890-10-1"  <- should be 1  
"abc123"           0                  "67890-10-2"  <- should be 2
```

This *violates* `uq_tx_onchain` (same tx_hash + same op_index), but the rows are kept distinct by the separate `uq_tx_horizon_op_id` constraint.

#### After Backfill
```
stellar_tx_hash    operation_index    horizon_op_id
"abc123"           0                  "67890-10-0"
"abc123"           1                  "67890-10-1"  
"abc123"           2                  "67890-10-2"
```

Now `uq_tx_onchain` is satisfied - each `(stellar_tx_hash, operation_index)` pair is unique.

### Constraint Interaction
- `uq_tx_horizon_op_id`: Ensures no duplicate TOID entries (already working)
- `uq_tx_onchain`: Ensures no duplicate `(tx_hash, op_index)` pairs (fixed by backfill)

## Usage

### Prerequisites
- Database connection with appropriate permissions
- Rust toolchain installed
- Environment variable `DATABASE_URL` set or passed via command line

### Basic Usage

```bash
# Dry run to see what would be changed
cargo run --bin backfill-operation-index -- --dry-run

# Run the actual backfill
cargo run --bin backfill-operation-index

# Custom batch size and database URL
cargo run --bin backfill-operation-index -- \
  --database-url postgresql://user:pass@host/db \
  --batch-size 500

# Limit processing to first 10,000 records
cargo run --bin backfill-operation-index -- --limit 10000
```

### Command Line Options

- `--database-url`: Database connection string (or set `DATABASE_URL` env var)
- `--batch-size`: Number of records to process per batch (default: 1000)
- `--dry-run`: Show what would be updated without making changes
- `--limit`: Maximum number of records to process (0 = unlimited)

## Safety Features

### Batch Processing
- Processes records in configurable batches (default: 1000)
- Uses database transactions to ensure consistency
- Small delays between batches to reduce database load
- No long-held table locks

### Idempotency
- Can be safely interrupted and restarted
- Skips records that already have correct values
- Uses optimistic locking to handle concurrent modifications

### Validation
- Validates TOID format before attempting updates
- Double-checks values haven't changed during processing
- Comprehensive logging of all actions taken

### Error Handling
- Continues processing even if individual updates fail
- Detailed error reporting and statistics
- Graceful handling of malformed data

## Rollout Plan

### Phase 1: Pre-deployment Preparation
1. **Test the backfill tool** against a copy of production data
2. **Verify constraint analysis** with real multi-operation transactions
3. **Measure performance** - estimate runtime for full dataset
4. **Plan maintenance window** if needed (tool is designed to run live)

### Phase 2: Forward Fix Deployment
1. **Deploy the forward-going fix first** (updated `Ingestor::process` method)
2. **Verify new deposits** get correct operation indices
3. **Monitor for any issues** with the new ingestion logic

### Phase 3: Historical Data Backfill
1. **Run backfill in dry-run mode** to validate the scope of changes
2. **Execute backfill during low-traffic period** (optional - tool is non-blocking)
3. **Monitor database performance** during backfill execution
4. **Verify constraint integrity** after completion

### Phase 4: Validation
1. **Query for any remaining incorrect records**
   ```sql
   SELECT COUNT(*) FROM transactions 
   WHERE direction = 'deposit' 
   AND horizon_op_id IS NOT NULL 
   AND operation_index != split_part(horizon_op_id, '-', 3)::int;
   ```
2. **Test end-to-end workflows** that depend on operation indices
3. **Monitor application metrics** for any anomalies

## Recommended Ordering

**The backfill should be run AFTER deploying the forward fix**, not before. Here's why:

1. **Minimize inconsistency window**: Deploy the fix first so new records are correct
2. **Reduce backfill scope**: Fewer records will need correction
3. **Enable safe rollback**: If issues arise, you can rollback the forward fix without affecting historical data
4. **Simplify troubleshooting**: Any issues will be isolated to either new data (forward fix) or historical data (backfill)

## Performance Characteristics

### Expected Runtime
- **Small datasets** (< 10K deposits): < 1 minute  
- **Medium datasets** (100K deposits): ~10 minutes
- **Large datasets** (1M+ deposits): 1-2 hours

### Database Impact
- **Minimal blocking**: Uses short transactions and small batches
- **Low CPU usage**: Simple SELECT and UPDATE operations
- **Moderate I/O**: Sequential reads with targeted updates
- **Safe for production**: Designed to run alongside normal operations

## Monitoring

The tool provides comprehensive statistics:
- Total records examined
- Records needing updates  
- Records successfully updated
- Errors encountered
- Invalid TOID formats found

Example output:
```
Backfill Summary:
  Total examined: 25000
  Needs update: 1250
  Updated: 1250  
  Skipped (already correct): 23750
  Skipped (invalid TOID): 0
  Errors: 0
```

## Testing

The tool includes comprehensive tests covering:
- TOID parsing edge cases
- Multi-operation transaction scenarios
- Constraint violation analysis
- Idempotency verification
- Error handling

Run tests with:
```bash
cargo test --bin backfill-operation-index
```
