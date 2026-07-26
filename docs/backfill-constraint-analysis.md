# Database Constraint Safety Analysis for Operation Index Backfill

## Executive Summary

The operation index backfill is **safe and will not violate database constraints**. The key insight is that the backfill actually *fixes* a constraint violation rather than causing one.

## Current State Problem

The `uq_tx_onchain` partial unique index on `(stellar_tx_hash, operation_index)` is currently violated by multi-operation transactions because all operations are recorded with `operation_index = 0`.

### Example: 3-Operation Transaction Before Backfill
```sql
stellar_tx_hash    operation_index    horizon_op_id     Status
"abc123"           0                  "67890-10-0"      ✓ Correct
"abc123"           0                  "67890-10-1"      ✗ Should be 1
"abc123"           0                  "67890-10-2"      ✗ Should be 2
```

**Constraint Status**: `uq_tx_onchain` is violated (duplicate keys), but rows remain distinct due to `uq_tx_horizon_op_id`.

## After Backfill State

### Same Transaction After Backfill
```sql
stellar_tx_hash    operation_index    horizon_op_id     Status
"abc123"           0                  "67890-10-0"      ✓ Correct
"abc123"           1                  "67890-10-1"      ✓ Fixed
"abc123"           2                  "67890-10-2"      ✓ Fixed
```

**Constraint Status**: `uq_tx_onchain` is now satisfied - all `(stellar_tx_hash, operation_index)` pairs are unique.

## Constraint Interaction Analysis

### Primary Constraints
1. **`uq_tx_horizon_op_id`**: Unique constraint on `horizon_op_id`
   - **Purpose**: Prevents duplicate TOID entries (idempotent ingestion)
   - **Status**: ✅ Already working correctly
   - **Impact**: Unaffected by backfill

2. **`uq_tx_onchain`**: Partial unique index on `(stellar_tx_hash, operation_index)` WHERE `stellar_tx_hash IS NOT NULL`
   - **Purpose**: Prevents double-crediting the same on-chain operation
   - **Status**: ❌ Currently violated for multi-op transactions
   - **Impact**: ✅ Fixed by backfill

### Why No Constraint Violations Occur During Backfill

The backfill updates records **individually**, changing their `operation_index` from the incorrect value `0` to the correct value parsed from the TOID. 

For each update:
- **Before**: `(tx_hash, 0)` - potentially duplicate key
- **After**: `(tx_hash, N)` where N is the correct operation index - unique key

Since each operation in a transaction has a different correct operation index (0, 1, 2, etc.), the updated records will all have unique `(stellar_tx_hash, operation_index)` pairs.

## Detailed Workflow Analysis

### Step-by-Step Update Process

Consider transaction "multi-tx" with 3 operations:

1. **Initial State** (all incorrect):
   ```
   Row A: ("multi-tx", 0) <- should be ("multi-tx", 0) ✓
   Row B: ("multi-tx", 0) <- should be ("multi-tx", 1) 
   Row C: ("multi-tx", 0) <- should be ("multi-tx", 2)
   ```

2. **After Row B Update**:
   ```
   Row A: ("multi-tx", 0) ✓
   Row B: ("multi-tx", 1) ✓ 
   Row C: ("multi-tx", 0) <- still needs update
   ```
   No constraint violation - keys are now `(multi-tx, 0)` and `(multi-tx, 1)`.

3. **After Row C Update**:
   ```
   Row A: ("multi-tx", 0) ✓
   Row B: ("multi-tx", 1) ✓
   Row C: ("multi-tx", 2) ✓
   ```
   No constraint violation - all keys are unique.

### Atomicity Guarantees

Each batch of updates is wrapped in a database transaction, ensuring:
- **Consistency**: Partial updates cannot leave the database in an inconsistent state
- **Isolation**: Concurrent operations see either the old state or the new state, never a mix
- **Rollback**: Any failure rolls back the entire batch, maintaining data integrity

## Edge Cases Analysis

### Case 1: Single Operation Transactions
- **Before**: `(tx_hash, 0)` - correct value
- **After**: `(tx_hash, 0)` - no change needed
- **Result**: No constraint impact

### Case 2: Already Fixed Transactions
- **Before**: `(tx_hash, N)` where N is already correct
- **After**: `(tx_hash, N)` - no change made
- **Result**: Idempotent - no constraint impact

### Case 3: High Operation Indices
- **Before**: `(tx_hash, 0)` - incorrect for operation 99
- **After**: `(tx_hash, 99)` - correct value
- **Result**: No constraint violation (99 is unique within this transaction)

### Case 4: Malformed TOIDs
- **Before**: `(tx_hash, 0)` - row with unparseable `horizon_op_id`
- **After**: `(tx_hash, 0)` - no change (skipped)
- **Result**: No constraint impact

## Rollback Safety

If the backfill needs to be rolled back:
1. The forward fix can be reverted to hardcode `operation_index = 0` again
2. Historical data can be restored from backups if needed
3. The constraint violation returns to its previous state (annoying but non-breaking)

## Concurrent Operations

The backfill is designed to handle concurrent database activity:
- Uses optimistic locking with WHERE clauses that check current values
- Small batch sizes minimize lock duration
- Failed individual updates are logged but don't stop the process
- Normal application operations can continue during backfill

## Conclusion

**The backfill operation is safe because it transforms the database from a state with constraint violations to a state with correct constraint satisfaction.** 

The `uq_tx_onchain` constraint is currently violated by the bug (multiple operations with the same `(tx_hash, operation_index)` pair) and will be fixed by the backfill (unique `(tx_hash, operation_index)` pairs for each operation).

No intermediate state during the backfill creates new constraint violations - each update moves from a violating state to a non-violating state.
