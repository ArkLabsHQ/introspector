# OP_MERKLEBRANCHVERIFY Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace OP_MERKLEPATHVERIFY (0xf4) with OP_MERKLEBRANCHVERIFY (0xb3) on the `feat/op-merklepathverify` branch, adding push-root semantics, raw hash mode, and proof chaining support.

**Architecture:** Single opcode at 0xb3 (OP_NOP4) that pops 4 stack items (leaf_tag, branch_tag, proof, leaf_data), computes a Merkle root using BIP-341 tagged hashes with lexicographic sibling ordering, and pushes the 32-byte result. Empty leaf_tag triggers raw hash mode (leaf_data used as-is). All work happens on the existing `feat/op-merklepathverify` branch.

**Tech Stack:** Go 1.25+, btcd/chaincfg/chainhash (TaggedHash), btcd/txscript

**Design doc:** `docs/plans/2026-03-02-op-merklebranchverify-design.md`

---

### Task 1: Rename constant and opcode table entry

All changes in `pkg/arkade/opcode.go` on branch `feat/op-merklepathverify`.

**Files:**
- Modify: `pkg/arkade/opcode.go:225` (constant definition)
- Modify: `pkg/arkade/opcode.go:305` (revert 0xf4)
- Modify: `pkg/arkade/opcode.go:525` (opcodeArray 0xb3)
- Modify: `pkg/arkade/opcode.go:606` (opcodeArray 0xf4)
- Modify: `pkg/arkade/opcode.go:750` (NOP handler)

**Step 1: Rename OP_NOP4 constant to OP_MERKLEBRANCHVERIFY**

At line 225, change:
```go
OP_NOP4                = 0xb3 // 179
```
to:
```go
OP_MERKLEBRANCHVERIFY  = 0xb3 // 179
```

**Step 2: Revert 0xf4 to OP_UNKNOWN244**

At line 305, change:
```go
OP_MERKLEPATHVERIFY     = 0xf4 // 244
```
to:
```go
OP_UNKNOWN244           = 0xf4 // 244
```

**Step 3: Update opcodeArray entry for 0xb3**

At line 525, change:
```go
OP_NOP4:  {OP_NOP4, "OP_NOP4", 1, opcodeNop},
```
to:
```go
OP_MERKLEBRANCHVERIFY:  {OP_MERKLEBRANCHVERIFY, "OP_MERKLEBRANCHVERIFY", 1, opcodeMerkleBranchVerify},
```

Note: `opcodeMerkleBranchVerify` does not exist yet — the build will fail until Task 3.

**Step 4: Revert opcodeArray entry for 0xf4**

At line 606, change:
```go
OP_MERKLEPATHVERIFY:     {OP_MERKLEPATHVERIFY, "OP_MERKLEPATHVERIFY", 1, opcodeMerklePathVerify},
```
to:
```go
OP_UNKNOWN244:           {OP_UNKNOWN244, "OP_UNKNOWN244", 1, opcodeInvalid},
```

**Step 5: Remove OP_NOP4 from NOP error handler**

At line 750, change:
```go
case OP_NOP1, OP_NOP4, OP_NOP5,
```
to:
```go
case OP_NOP1, OP_NOP5,
```

**Step 6: Update all references to old constant names**

Search for any remaining `OP_NOP4` or `OP_MERKLEPATHVERIFY` references in `opcode.go` and update them. There should be none after steps 1-5.

---

### Task 2: Update opcode_test.go disasm expectations

**Files:**
- Modify: `pkg/arkade/opcode_test.go:75`
- Modify: `pkg/arkade/opcode_test.go:129`
- Modify: `pkg/arkade/opcode_test.go:205`

**Step 1: Update expected strings map**

At line 75, change:
```go
0xf4: "OP_MERKLEPATHVERIFY",
```
to:
```go
0xb3: "OP_MERKLEBRANCHVERIFY",
```

**Step 2: Fix unknown range for 0xf3-0xf9**

At line 129, change:
```go
(opcodeVal >= 0xf3 && opcodeVal <= 0xf9 && opcodeVal != 0xf4) || // Unknown range after new ops
```
to:
```go
(opcodeVal >= 0xf3 && opcodeVal <= 0xf9) || // Unknown range after new ops
```

**Step 3: Same fix in second test block**

At line 205, make the same change:
```go
(opcodeVal >= 0xf3 && opcodeVal <= 0xf9 && opcodeVal != 0xf4) || // Unknown range after new ops
```
to:
```go
(opcodeVal >= 0xf3 && opcodeVal <= 0xf9) || // Unknown range after new ops
```

**Step 4: Handle 0xb3 in unknown ranges**

In both test blocks, 0xb3 currently falls under the NOP range. Find the NOP handling case:
```go
case opcodeVal >= 0xb0 && opcodeVal <= 0xba:
```
This range already covers 0xb0-0xba. Since 0xb3 is now OP_MERKLEBRANCHVERIFY (in the expected strings map), and 0xb1 (CHECKLOCKTIMEVERIFY) and 0xb2 (CHECKSEQUENCEVERIFY) are also special-cased in the map, the existing logic should handle it: the map lookup takes precedence over the range case. Verify this by reading the test structure — the `expectedStrings` map is checked first.

---

### Task 3: Write failing tests for new behavior

**Files:**
- Modify: `pkg/arkade/engine_test.go:1408-1640` (replace TestMerklePathVerify)

**Step 1: Rename test function and rewrite**

Replace the entire `TestMerklePathVerify` function (lines 1408-1640) with `TestMerkleBranchVerify`. The key changes:
- Script uses `OP_MERKLEBRANCHVERIFY` (0xb3) instead of `OP_MERKLEPATHVERIFY` (0xf4)
- Script appends `<expected_root> OP_EQUALVERIFY` after the opcode (since it pushes root, not verifies internally)
- No `expected_root` in the pre-loaded stack
- Add new test cases: raw hash mode, proof chaining, two-leaf same-tree

The test script pattern changes from:
```go
// OLD: OP_MERKLEPATHVERIFY OP_TRUE
builder := txscript.NewScriptBuilder().
    AddOp(OP_MERKLEPATHVERIFY).
    AddOp(OP_TRUE)
```
to:
```go
// NEW: OP_MERKLEBRANCHVERIFY <expected_root> OP_EQUALVERIFY OP_TRUE
builder := txscript.NewScriptBuilder().
    AddOp(OP_MERKLEBRANCHVERIFY).
    AddData(tc.expectedRoot).
    AddOp(txscript.OP_EQUALVERIFY).
    AddOp(OP_TRUE)
```

And the stack no longer includes `expected_root` at the top — it's just:
```go
stack: [][]byte{
    leafTag,         // leaf_tag (bottom)
    branchTag,       // branch_tag
    siblingHash,     // proof
    []byte("hello"), // leaf_data (top)
},
```

**Test cases to include:**

1. `valid_2leaf_tree` — tagged hash mode, 1-sibling proof, verify pushed root
2. `valid_4leaf_tree` — tagged hash mode, 2-sibling proof
3. `valid_single_leaf_empty_proof` — empty proof, leaf hash IS the root
4. `valid_raw_hash_mode` — empty leaf_tag, 32-byte leaf_data used as-is
5. `valid_proof_chaining` — two calls: first computes sub-root, second uses it in raw mode to compute real root
6. `valid_two_leaf_same_tree` — two calls on different leaves, EQUALVERIFY both roots match
7. `invalid_wrong_root` — pushed root doesn't match expected, EQUALVERIFY fails
8. `invalid_proof_not_multiple_of_32` — 33-byte proof
9. `invalid_empty_branch_tag` — empty branch_tag
10. `invalid_raw_mode_leaf_not_32_bytes` — empty leaf_tag but leaf_data is 10 bytes
11. `invalid_empty_leaf_tag_nonempty_but_wrong_size` — variant of raw mode validation

**Step 2: Run tests to verify they fail**

Run: `go test github.com/ArkLabsHQ/introspector/pkg/arkade -run TestMerkleBranchVerify -v`
Expected: FAIL (compile error — `opcodeMerkleBranchVerify` not defined yet)

---

### Task 4: Implement opcodeMerkleBranchVerify

**Files:**
- Modify: `pkg/arkade/opcode.go:3122-3205` (replace opcodeMerklePathVerify)

**Step 1: Replace the implementation**

Delete `opcodeMerklePathVerify` (lines 3122-3205) and write `opcodeMerkleBranchVerify`:

```go
// opcodeMerkleBranchVerify computes a Merkle root from a leaf and proof
// path using BIP-341 tagged hashes with lexicographic sibling ordering.
//
// Stack inputs (top to bottom): leaf_data, proof, branch_tag, leaf_tag
// Stack output: computed_root (32 bytes)
//
// If leaf_tag is empty, leaf_data must be exactly 32 bytes and is used
// as a raw hash (enables proof chaining). If leaf_tag is non-empty,
// the leaf hash is computed as tagged_hash(leaf_tag, leaf_data).
//
// At each proof step, siblings are sorted lexicographically before
// hashing: tagged_hash(branch_tag, min || max).
func opcodeMerkleBranchVerify(op *opcode, data []byte, vm *Engine) error {
	// Pop leaf_data
	leafData, err := vm.dstack.PopByteArray()
	if err != nil {
		return err
	}

	// Pop proof (must be multiple of 32 bytes)
	proof, err := vm.dstack.PopByteArray()
	if err != nil {
		return err
	}
	if len(proof)%32 != 0 {
		return scriptError(txscript.ErrInvalidStackOperation,
			"proof length must be a multiple of 32")
	}

	// Pop branch_tag (must not be empty)
	branchTag, err := vm.dstack.PopByteArray()
	if err != nil {
		return err
	}
	if len(branchTag) == 0 {
		return scriptError(txscript.ErrInvalidStackOperation,
			"branch_tag must not be empty")
	}

	// Pop leaf_tag (empty = raw hash mode)
	leafTag, err := vm.dstack.PopByteArray()
	if err != nil {
		return err
	}

	// Compute leaf hash
	var current []byte
	if len(leafTag) == 0 {
		// Raw hash mode: leaf_data must be exactly 32 bytes
		if len(leafData) != 32 {
			return scriptError(txscript.ErrInvalidStackOperation,
				"raw hash mode requires leaf_data to be 32 bytes")
		}
		current = leafData
	} else {
		h := chainhash.TaggedHash(leafTag, leafData)
		current = h[:]
	}

	// Walk the proof path with lexicographic ordering
	for i := 0; i < len(proof); i += 32 {
		sibling := proof[i : i+32]
		combined := make([]byte, 64)
		if bytes.Compare(current, sibling) < 0 {
			copy(combined[:32], current)
			copy(combined[32:], sibling)
		} else {
			copy(combined[:32], sibling)
			copy(combined[32:], current)
		}
		h := chainhash.TaggedHash(branchTag, combined)
		current = h[:]
	}

	// Push computed root
	vm.dstack.PushByteArray(current)
	return nil
}
```

**Step 2: Run tests**

Run: `go test github.com/ArkLabsHQ/introspector/pkg/arkade -run TestMerkleBranchVerify -v`
Expected: PASS for all test cases

**Step 3: Run full test suite**

Run: `go test github.com/ArkLabsHQ/introspector/pkg/arkade -v`
Expected: All tests PASS (including TestOpcodeDisasm, TestNewOpcodes, etc.)

**Step 4: Commit**

```bash
git add pkg/arkade/opcode.go pkg/arkade/opcode_test.go pkg/arkade/engine_test.go
git commit -m "feat: replace OP_MERKLEPATHVERIFY with OP_MERKLEBRANCHVERIFY

Moves from opcode 0xf4 to 0xb3 (OP_NOP4), matching BIP-116's slot.
Pushes computed root instead of failing on mismatch, enabling proof
chaining and 2-of-N same-tree patterns. Adds raw hash mode (empty
leaf_tag) for chaining sub-roots between calls."
```

---

### Task 5: Update README opcode table

**Files:**
- Modify: `README.md:297` (replace OP_MERKLEPATHVERIFY row)

**Step 1: Replace the table row**

At line 297, change the OP_MERKLEPATHVERIFY row to:

```markdown
| OP_MERKLEBRANCHVERIFY | 179 | 0xb3 | leaf_tag branch_tag proof leaf_data | computed_root | Computes a Merkle root using BIP-341 tagged hashes. If leaf_tag is empty, leaf_data (32 bytes) is used as a raw hash; otherwise computes `tagged_hash(leaf_tag, leaf_data)`. Walks the proof path with lexicographic sibling ordering. Pushes the 32-byte computed root. Use with `OP_EQUALVERIFY` to verify against an expected root. |
```

Move it from the Cryptography section to be placed correctly — 0xb3 is in the NOP range, but semantically it belongs in Cryptography.

**Step 2: Commit**

```bash
git add README.md
git commit -m "docs: update README for OP_MERKLEBRANCHVERIFY"
```

---

### Task 6: Push and verify CI

**Step 1: Push the branch**

```bash
git push origin feat/op-merklepathverify
```

**Step 2: Check CI**

```bash
gh pr checks 11
```

Expected: All checks pass (unit, lint, format, integration, build).
