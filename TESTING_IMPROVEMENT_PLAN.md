# Testing Coverage Improvement Plan - Introspector

## Executive Summary

This plan addresses gaps in test coverage for the asset introspection opcodes implementation. Focus areas: missing unit tests for 14 new opcodes, compilation-blocking import errors, missing negative test cases, and infrastructure for comprehensive testing.

---

## 1. Critical Fixes (Blocks Compilation)

### 1.1 Missing Imports - P0 BLOCKER

**File: `test/settlement_asset_test.go`**
```go
// Line 104 uses btcec.NewPrivateKey() but btcec/v2 not imported
import (
    // Add:
    "github.com/btcsuite/btcd/btcec/v2"
)
```

**File: `test/asset_test.go`**
```go
// Line 63 uses txscript.NewBaseTapLeaf() but txscript not imported  
import (
    // Add:
    "github.com/btcsuite/btcd/txscript"
)
```

**Effort**: 5 minutes  
**Impact**: Unblocks build

---

## 2. Unit Tests for Asset Opcodes - P1

**Current state**: 0% unit test coverage for 14 asset opcodes  
**Target**: 80%+ coverage with comprehensive edge cases

### Create `pkg/arkade/asset_opcodes_test.go`

Template for all opcode tests:

```go
func TestOpcodeXYZ(t *testing.T) {
    tests := []struct {
        name        string
        setup       func(*Engine)
        assetPacket asset.Packet
        want        []interface{}  // expected stack
        wantErr     string
    }{
        {name: "happy path", ...},
        {name: "edge case", ...},
        {name: "error case", wantErr: "expected error"},
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            vm := makeTestVM(tt.assetPacket)
            if tt.setup != nil {
                tt.setup(vm)
            }
            
            err := opcodeXYZ(nil, nil, vm)
            
            if tt.wantErr != "" {
                require.Error(t, err)
                require.Contains(t, err.Error(), tt.wantErr)
                return
            }
            
            require.NoError(t, err)
            assertStack(t, tt.want, vm.dstack)
        })
    }
}
```

### 2.1 Opcode Test Coverage Checklist

- [ ] **OP_INSPECTNUMASSETGROUPS** (0xe5)
  - Empty packet → error
  - Single group → 1
  - Multiple groups → N

- [ ] **OP_INSPECTASSETGROUPASSETID** (0xe6)
  - Fresh issuance (AssetId=nil) → tx.hash + group index
  - Existing asset → AssetId.Txid + Index
  - Out of bounds → error

- [ ] **OP_INSPECTASSETGROUPCTRL** (0xe7)
  - No control → -1
  - Control by ID → AssetId
  - Control by Group (fresh) → tx.hash + index (**critical test for nil fix**)
  - Control by Group (existing) → resolved AssetId
  - Out of bounds GroupIndex → error

- [ ] **OP_FINDASSETGROUPBYASSETID** (0xe8)
  - Found → group index
  - Not found → -1
  - Search fresh asset → found

- [ ] **OP_INSPECTASSETGROUPMETADATAHASH** (0xe9)
  - Empty metadata → zero hash
  - Single entry → hash
  - Multiple entries → Merkle root
  - Serialization error → error (**critical test for error handling fix**)

- [ ] **OP_INSPECTASSETGROUPNUM** (0xea)
  - source=0 → input count
  - source=1 → output count
  - source=2 → both counts
  - Invalid source → error

- [ ] **OP_INSPECTASSETGROUP** (0xeb)
  - LOCAL input → type + vin + amount
  - INTENT input → type + txid + vin + amount
  - Output → type + vout + amount
  - Out of bounds → error

- [ ] **OP_INSPECTASSETGROUPSUM** (0xec)
  - Overflow uint64 → error
  - source=0/1/2 → correct sums

- [ ] **OP_INSPECTOUTASSETCOUNT** (0xed)
  - Multiple assets same output → count

- [ ] **OP_INSPECTOUTASSETAT** (0xee)
  - Index across groups → correct asset

- [ ] **OP_INSPECTOUTASSETLOOKUP** (0xef)
  - Found → amount
  - Not found → -1

- [ ] **OP_INSPECTINASSETCOUNT** (0xf0)
- [ ] **OP_INSPECTINASSETAT** (0xf1)
- [ ] **OP_INSPECTINASSETLOOKUP** (0xf2)

**Effort**: 2-3 days  
**Impact**: Core correctness assurance

---

## 3. Helper Function Tests - P1

### 3.1 Merkle Root Computation

```go
func TestComputeMetadataMerkleRoot(t *testing.T) {
    t.Run("empty metadata", ...)
    t.Run("single entry", ...)
    t.Run("even number (2)", ...)
    t.Run("odd number (3)", ...)
    t.Run("serialization error", ...) // Test error propagation fix
    t.Run("deterministic", ...) // Same input → same output
}
```

### 3.2 Safe Sum Functions

```go
func TestSafeSumInputs(t *testing.T) {
    t.Run("empty", ...)
    t.Run("single", ...)
    t.Run("uint64 overflow", ...) // max + 1 → big.Int > uint64
}
```

**Effort**: 4 hours

---

## 4. Integration Test Negative Cases - P1

Current tests only validate happy paths. Add failure scenarios:

### 4.1 In `test/asset_test.go`

```go
func TestOffchainTxWithAsset(t *testing.T) {
    // Existing happy path...
    
    t.Run("wrong asset amount", func(t *testing.T) {
        assetPacket := createAssetPacket(t, 0, 1000)
        arkadeScript := createArkadeScriptWithAssetChecks(t, alicePkScript, 500) // mismatch!
        
        // Build and submit tx
        _, _, err := introspectorClient.SubmitTx(...)
        require.Error(t, err)
        require.Contains(t, err.Error(), "OP_EQUAL")
    })
    
    t.Run("missing asset packet", ...)
    t.Run("wrong group count", ...)
    t.Run("not an issuance", ...)
}
```

### 4.2 In `test/settlement_asset_test.go`

Similar negative cases for intent flow.

**Effort**: 1 day  
**Impact**: Prevents regressions

---

## 5. Test Infrastructure - P1

### 5.1 Create `pkg/arkade/testutil_test.go`

```go
// makeTestVM creates minimal VM for opcode testing
func makeTestVM(assetPacket asset.Packet) *Engine {
    return &Engine{
        tx:          wire.NewMsgTx(2),
        assetPacket: assetPacket,
        dstack:      stack{},
    }
}

// makeTestPacket creates packet with N groups
func makeTestPacket(n int) asset.Packet {
    groups := make([]asset.AssetGroup, n)
    for i := 0; i < n; i++ {
        groups[i] = makeTestGroup(i, false)
    }
    packet, _ := asset.NewPacket(groups)
    return packet
}

// makeTestGroup with configurable fresh/existing asset
func makeTestGroup(index int, fresh bool) asset.AssetGroup {
    var assetId *asset.AssetId
    if !fresh {
        assetId = &asset.AssetId{
            Txid:  chainhash.HashH([]byte(fmt.Sprintf("asset-%d", index))),
            Index: uint16(index),
        }
    }
    
    group, _ := asset.NewAssetGroup(
        assetId,
        nil, // control asset
        []asset.AssetInput{{Vin: uint32(index), Amount: 1000}},
        []asset.AssetOutput{{Vout: uint16(index), Amount: 1000}},
        []asset.Metadata{},
    )
    return *group
}
```

**Effort**: 4 hours  
**Impact**: Enables all unit tests

---

## 6. Edge Cases & Boundaries - P2

### 6.1 Boundary Tests

```go
func TestAssetOpcodeBoundaries(t *testing.T) {
    t.Run("max groups (1000)", ...)
    t.Run("negative index", ...)
    t.Run("index == len", ...)
    t.Run("max uint64 amounts", ...)
    t.Run("empty inputs/outputs", ...)
}
```

### 6.2 Multi-Asset Scenarios

```go
func TestMultiAssetUTXO(t *testing.T) {
    // 3 asset groups all outputting to output 0
    // Test OP_INSPECTOUTASSETCOUNT → 3
    // Test OP_INSPECTOUTASSETAT can retrieve all
}
```

**Effort**: 1 day

---

## 7. Advanced Testing - P3

### 7.1 Fuzz Testing

```go
func FuzzAssetOpcodeInvariants(f *testing.F) {
    f.Fuzz(func(t *testing.T, numGroups uint8) {
        if numGroups == 0 || numGroups > 100 {
            t.Skip()
        }
        
        packet := makeTestPacket(int(numGroups))
        
        // Invariant: count always equals actual groups
        // Invariant: valid indices [0, count) never error
        // ...
    })
}
```

**Effort**: 1-2 days

---

## 8. CI & Automation - P2

### 8.1 Coverage Enforcement

```yaml
# .github/workflows/test.yml
- name: Test with coverage
  run: go test -v -coverprofile=coverage.out ./...

- name: Check threshold
  run: |
    COVERAGE=$(go tool cover -func=coverage.out | grep total | awk '{print $3}' | sed 's/%//')
    if (( $(echo "$COVERAGE < 70.0" | bc -l) )); then
      echo "Coverage $COVERAGE% below 70% threshold"
      exit 1
    fi
```

**Effort**: 2 hours

---

## Implementation Phases

### **Phase 1: Unblock (Week 1)** - P0/P1
- [ ] Fix import errors
- [ ] Create test infrastructure
- [ ] 5 example opcode unit tests
- [ ] 2 helper function tests

**Deliverable**: Tests compile and pass

### **Phase 2: Coverage (Week 2-3)** - P1
- [ ] Complete all 14 opcode unit tests
- [ ] All helper function tests
- [ ] Integration negative tests

**Deliverable**: 70%+ coverage

### **Phase 3: Quality (Week 4)** - P2
- [ ] Edge case tests
- [ ] Multi-asset scenarios
- [ ] CI coverage checks

**Deliverable**: Robust test suite

### **Phase 4: Advanced (Optional)** - P3
- [ ] Fuzz testing
- [ ] Property-based tests
- [ ] Performance benchmarks

---

## Success Metrics

**Before**:
- Asset opcodes: 0% unit coverage
- Tests: happy path only
- Build: broken (import errors)

**After Phase 1**:
- Build: ✓ fixed
- Coverage: ~30%
- Path: clear

**After Phase 2**:
- Coverage: 70%+
- Tests: positive + negative
- Confidence: high

**Target**:
- Coverage: 80%+
- All opcodes: unit tested
- CI: enforced
- Docs: complete

---

## Quick Start

1. **Fix imports now**:
   ```bash
   # test/settlement_asset_test.go
   import "github.com/btcsuite/btcd/btcec/v2"
   
   # test/asset_test.go  
   import "github.com/btcsuite/btcd/txscript"
   ```

2. **Create test infrastructure**:
   ```bash
   touch pkg/arkade/testutil_test.go
   # Copy helpers from section 5.1
   ```

3. **First opcode test**:
   ```bash
   touch pkg/arkade/asset_opcodes_test.go
   # Start with OP_INSPECTNUMASSETGROUPS from section 2.1
   ```

4. **Run and iterate**:
   ```bash
   go test ./pkg/arkade/... -v
   ```

---

## Maintenance

- Add tests alongside any new opcodes
- Run `go test -cover ./...` before commits
- Keep helpers in `testutil_test.go` updated
- Review coverage weekly
