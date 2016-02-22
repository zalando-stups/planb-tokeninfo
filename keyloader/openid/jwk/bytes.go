package jwk

import (
	"encoding/base64"
	"encoding/json"
	"math/big"
)

type base64Bytes []byte

func (b *base64Bytes) UnmarshalJSON(data []byte) error {
	var out string
	if err := json.Unmarshal(data, &out); err != nil {
		return err
	}

	if out == "" {
		return nil
	}

	decoded, err := base64.RawURLEncoding.DecodeString(out)
	if err != nil {
		return err
	}

	*b = base64Bytes(decoded)

	return nil
}

func (b *base64Bytes) toBigInt() *big.Int {
	return new(big.Int).SetBytes([]byte(*b))
}

func (b *base64Bytes) toInt() int {
	return int(b.toBigInt().Int64())
}
