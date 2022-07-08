package internal

import (
	"fmt"
	"testing"
)

func TestMakeAesCFB(t *testing.T) {
	key := []byte("zzzzzzwwwwwfffgg")
	o := MakeAesCFB(key)
	en, err := o.Encrypt([]byte("hello 你好，world 世界"))
	if err != nil {
		t.Errorf("Encrypt err : %+v", err)
	}
	fmt.Println("Encrypt: ", string(en))

	de, err := o.Decrypt(en)
	if err != nil {
		t.Errorf("Decrypt err : %+v", err)
	}
	fmt.Println("Decrypt: ", string(de))
}
