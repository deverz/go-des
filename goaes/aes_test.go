package goaes

import (
	"testing"
)

/*
 * @Desc:
 * @Author: zhangbingbing2@tal.com
 * @File: goaes/aes_test.go.go
 * @Date: 2022/2/10 2:53 下午
 */
const aesKey = "4cca1291174cf02dc471df969f5d6fef"

func TestEnAesBase64(t *testing.T) {
	sourceData := "1234567你好世界-*7……！~、的"
	s,err:=EnAesBase64(sourceData, aesKey)
	if err!=nil{
		t.Errorf("%v",err)
		return
	}
	t.Log(string(s))
	// yom7qdAWG42-SXrH4cWFth5J1FCOndashpnmXriNf7UYnab1iAX1rcKQeQwTq8lMgqbXcJTfLiGvZvkaklPBug
}

func TestDeAesBase64(t *testing.T) {
	//encryptString := "cWXC-u8es0xh65TAe2_I55TRvFjYPlwGZbWbz8eJitFX9tKtkT8AeHBTe9qrhaZnJQmVoTN-HLT1WJULyumQkg"
	encryptString := "7ecef1d6-3e8b-4eb2-9141-9fe913287e3d"
	s,err:=DeAesBase64(encryptString, aesKey)
	if err!=nil{
		t.Errorf("%v",err)
		return
	}
	t.Log(string(s))
}