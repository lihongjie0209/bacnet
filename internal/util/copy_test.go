package util

import (
	"bytes"
	"slices"
	"testing"
)

func TestCloneBytes(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
		want []byte
	}{
		{name: "empty", in: []byte{}, want: []byte{}},
		{name: "non-empty", in: []byte{1, 2, 3}, want: []byte{1, 2, 3}},
		{name: "nil", in: nil, want: []byte{}},
	}

	for _, tt := range tests {
		res := slices.Clone(tt.in)
		if !bytes.Equal(res, tt.want) {
			t.Errorf("%s: CloneBytes() = %v, want %v", tt.name, res, tt.want)
		}
	}
}

func TestCloneBytes_ChangedValue(t *testing.T) {
	in := []byte{1, 2, 3}
	want := []byte{1, 2, 3}

	res := slices.Clone(in)

	in[0] += 1

	// test copy behavior
	if !bytes.Equal(want, res) {
		t.Errorf("CloneBytes() returned same slice")
	}
}

func TestCopyPointersValue(t *testing.T) {
	tests := []struct {
		name string
		in   *int
		want *int
	}{
		{name: "nil", in: nil, want: nil},
		{name: "int", in: ptr(10), want: ptr(10)},
	}

	for _, tt := range tests {
		res := CopyPointersValue(tt.in)
		if tt.want == nil {
			if res != nil {
				t.Errorf("%s: CopyPointersValue() = %v, want nil", tt.name, res)
			}

			continue // skip rest to prevent nil dereference of tt.want or tt.in
		}

		if res != nil && *res != *tt.want {
			t.Errorf("%s: CopyPointersValue() = %v, want %v", tt.name, res, tt.want)
		}

		*tt.in = *tt.in + 1

		if res != nil && *tt.want != *res {
			t.Errorf("%s: CopyPointersValue() rresult changed after input changed: %v, want %v", tt.name, res, tt.want)
		}

	}
}
