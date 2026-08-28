package arkade

import (
	"bytes"
	"testing"

	"github.com/btcsuite/btcd/txscript"
	"github.com/stretchr/testify/require"
)

func inspectIntentMessageSpec() *opcodeSpec {
	message := []byte(`{"type":"register","expire_at":1000,"enabled":false,"items":[1,2]}`)
	setupMessage := WithIntentMessage(message)

	return &opcodeSpec{
		opcode:          OP_INSPECTINTENTMESSAGE,
		checkProperties: inspectIntentMessagePropertyChecker,
		validVectors: []opcodeVector{
			{
				name:          "no_context",
				inputStack:    [][]byte{[]byte("type")},
				expectedStack: [][]byte{nil, nil},
			},
			{
				name:          "string",
				inputStack:    [][]byte{[]byte("type")},
				setupVM:       setupMessage,
				expectedStack: [][]byte{[]byte("register"), {1}},
			},
			{
				name:          "integer",
				inputStack:    [][]byte{[]byte("expire_at")},
				setupVM:       setupMessage,
				expectedStack: [][]byte{scriptNum(1000).Bytes(), {1}},
			},
			{
				name:          "false_value_is_present",
				inputStack:    [][]byte{[]byte("enabled")},
				setupVM:       setupMessage,
				expectedStack: [][]byte{nil, {1}},
			},
			{
				name:          "json",
				inputStack:    [][]byte{[]byte("items")},
				setupVM:       setupMessage,
				expectedStack: [][]byte{[]byte("[1,2]"), {1}},
			},
			{
				name:          "array_index",
				inputStack:    [][]byte{[]byte("items.0")},
				setupVM:       setupMessage,
				expectedStack: [][]byte{scriptNum(1).Bytes(), {1}},
			},
			{
				name:          "missing",
				inputStack:    [][]byte{[]byte("missing")},
				setupVM:       setupMessage,
				expectedStack: [][]byte{nil, nil},
			},
			{
				name:       "non_integer",
				inputStack: [][]byte{[]byte("value")},
				setupVM: func(vm *Engine) {
					WithIntentMessage([]byte(`{"value":1e-1}`))(vm)
				},
				expectedStack: [][]byte{nil, nil},
			},
			{
				name:          "complex_path_is_miss",
				inputStack:    [][]byte{[]byte("items.#")},
				setupVM:       setupMessage,
				expectedStack: [][]byte{nil, nil},
			},
		},
		invalidVectors: []opcodeVector{
			{name: "underflow", expectedError: txscript.ErrInvalidStackOperation},
			{
				name:       "oversized_result",
				inputStack: [][]byte{[]byte("value")},
				setupVM: func(vm *Engine) {
					raw := []byte(`{"value":"` +
						string(bytes.Repeat([]byte{'a'}, txscript.MaxScriptElementSize+1)) + `"}`)
					WithIntentMessage(raw)(vm)
				},
				expectedError: txscript.ErrElementTooBig,
			},
			{
				name:       "oversized_integer",
				inputStack: [][]byte{[]byte("value")},
				setupVM: func(vm *Engine) {
					WithIntentMessage([]byte(`{"value":1e2000}`))(vm)
				},
				expectedError: txscript.ErrNumberTooBig,
			},
			{
				name:       "oversized_message",
				inputStack: [][]byte{[]byte("type")},
				setupVM: func(vm *Engine) {
					WithIntentMessage(make([]byte, maxIntentMessageSize+1))(vm)
				},
				expectedError: txscript.ErrScriptTooBig,
			},
		},
	}
}

func inspectIntentMessagePropertyChecker(t *testing.T, c opcodeCheckContext) {
	t.Helper()
	require.Equal(t, c.before.GetAltStack(), c.after.GetAltStack())
	require.Equal(t, c.before.condStack, c.after.condStack)

	beforeDepth := len(c.before.GetStack())
	afterDepth := len(c.after.GetStack())
	if c.execErr != nil {
		requireScriptErrorCodeIn(t, c.execErr,
			txscript.ErrInvalidStackOperation,
			txscript.ErrNumberTooBig,
			txscript.ErrElementTooBig,
			txscript.ErrScriptTooBig,
		)
		require.True(t, afterDepth == beforeDepth || afterDepth == beforeDepth-1)
		return
	}

	require.Equal(t, beforeDepth+1, afterDepth)
	flag := c.after.GetStack()[afterDepth-1]
	require.True(t, bytes.Equal(flag, nil) || bytes.Equal(flag, []byte{1}))
	require.LessOrEqual(t, len(c.after.GetStack()[afterDepth-2]), txscript.MaxScriptElementSize)
}

func TestSimpleIntentMessagePath(t *testing.T) {
	t.Parallel()

	for _, path := range []string{"type", "nested.value", "items.0", "a_b"} {
		require.True(t, isSimpleIntentMessagePath([]byte(path)), path)
	}
	for _, path := range []string{"", ".type", "type.", "a..b", "*", "items.#", "@this", "items.#(type)", "a|b", "Type"} {
		require.False(t, isSimpleIntentMessagePath([]byte(path)), path)
	}
}

func TestParseJSONInteger(t *testing.T) {
	t.Parallel()

	tests := []struct {
		raw     string
		want    string
		integer bool
	}{
		{raw: "1", want: "1", integer: true},
		{raw: "-0", want: "0", integer: true},
		{raw: "1.0", want: "1", integer: true},
		{raw: "1e3", want: "1000", integer: true},
		{raw: "10e-1", want: "1", integer: true},
		{raw: "1.5e1", want: "15", integer: true},
		{raw: "1e-1", integer: false},
		{raw: "1.5", integer: false},
		{raw: "1e-9223372036854775808", integer: false},
		{raw: "1e-999999999", integer: false},
	}

	for _, test := range tests {
		t.Run(test.raw, func(t *testing.T) {
			t.Parallel()
			got, integer, err := parseJSONInteger(test.raw)
			require.NoError(t, err)
			require.Equal(t, test.integer, integer)
			if integer {
				require.Equal(t, test.want, got.String())
			}
		})
	}

	_, _, err := parseJSONInteger("1e999999999")
	requireScriptErrorCode(t, err, txscript.ErrNumberTooBig)
}

func BenchmarkInspectIntentMessage4MiB(b *testing.B) {
	prefix := []byte(`{"padding":"`)
	suffix := []byte(`","type":"register"}`)
	message := append(prefix, bytes.Repeat([]byte{'a'}, maxIntentMessageSize-len(prefix)-len(suffix))...)
	message = append(message, suffix...)
	vm := &Engine{intentMessage: message}

	b.ReportAllocs()
	b.SetBytes(int64(len(message)))
	for b.Loop() {
		vm.SetStack([][]byte{[]byte("type")})
		if err := opcodeInspectIntentMessage(nil, nil, vm); err != nil {
			b.Fatal(err)
		}
	}
}
