package jwk

import (
	"math/big"
	"reflect"
	"testing"
)

func TestBytes(t *testing.T) {
	for _, test := range []struct {
		in         string
		want       *base64Bytes
		wantBigInt *big.Int
		wantInt    int
		wantError  bool
	}{
		{"", nil, nil, 0, true},
		{`"A"`, nil, nil, 0, true},
		{`""`, nil, nil, 0, false},
		{`"CBU"`, &base64Bytes{0x08, 0x15}, big.NewInt(2069), 2069, false},
	} {
		var got *base64Bytes
		if test.want != nil {
			got = &base64Bytes{}
		}
		err := got.UnmarshalJSON([]byte(test.in))
		if test.wantError && err == nil {
			t.Error("Wanted an error but err was nil")
		}

		if !reflect.DeepEqual(test.want, got) {
			t.Errorf("Unexpected output. Wanted %v, got %v", test.want, got)
		}

		if test.want != nil {
			gotBigInt := got.toBigInt()
			if test.wantBigInt.Cmp(gotBigInt) != 0 {
				t.Errorf("Unexpected BigInt value. Wanted %v, got %v", test.wantBigInt, gotBigInt)
			}
			gotInt := got.toInt()
			if gotInt != test.wantInt {
				t.Errorf("Unexpected Int value. Wanted %v, got %v", test.wantInt, gotInt)
			}
		}
	}
}
