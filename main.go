package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/atotto/clipboard"
)

const (
	en_symbol  = "+"
	de_symbol  = "$"
	key_symbol = "="
)

func main() {

	fmt.Printf(`
1. Encrypt: input message like "%smessge%spassword", then copy it
2. Decrypt: add password after last '%s' of ciphertext, then copy it

3. all encrypt or decrypt result will write to system Clipboard, So easy!!
`, en_symbol, key_symbol, key_symbol)

	listenClipboard(context.Background())

	for {
		time.Sleep(20 * time.Second)
	}
}

func listenClipboard(ctx context.Context) {

	go func(ctx context.Context) {
		for {
			time.Sleep(1 * time.Second)

			select {
			case <-ctx.Done():
				fmt.Println("stoped")
				return
			default:
				//读取剪贴板内容
				content, err := clipboard.ReadAll()
				if err != nil {
					panic(err)
				}

				//去掉前后空白
				content = strings.TrimSpace(content)

				switch {
				case content[:1] == en_symbol && !strings.HasSuffix(content, key_symbol) && strings.Index(content, key_symbol) > 0:
					if newcontent := EncryptByKey(content); newcontent != "" {
						err := clipboard.WriteAll(newcontent)
						if err != nil {
							panic(err)
						}
						fmt.Println("Copied it")
					}

				case content[:1] == de_symbol && !strings.HasSuffix(content, key_symbol):
					if newcontent := DecryptByKey(content); newcontent != "" {
						err := clipboard.WriteAll(newcontent)
						if err != nil {
							panic(err)
						}
						fmt.Println("Copied it")
					}

				}

			}

		}
	}(ctx)

}

func EncryptByKey(v string) (r string) {

	fmt.Println("Encrypting")
	defer fmt.Println("over")

	_s := strings.Split(v[1:], key_symbol)

	if len(_s) < 2 || _s[len(_s)-1] == "" {
		fmt.Println("no passwrod input")
		return ""
	}

	r, err := EncryptByString(strings.Join(_s[:len(_s)-1], key_symbol), _s[len(_s)-1])
	if err != nil {
		return err.Error()
	}

	//如果是密码加密模式，会在尾部加上 key_symbol,否则为空字符串
	r = fmt.Sprintf("%s%s:%s%s", de_symbol, r, MD5(strings.Join(_s[:len(_s)-1], key_symbol)), key_symbol)

	fmt.Println("Encrypt to:" + r)
	return
}

func DecryptByKey(v string) (r string) {

	fmt.Println("Decrypting...")
	defer fmt.Println("over")

	_s := strings.Split(v[1:], ":") //用：分割

	if len(_s) != 2 {
		fmt.Println("no check string")
		return ""
	}

	_c := strings.Split(_s[1], key_symbol)
	if len(_c) != 2 || _c[1] == "" {
		fmt.Println("no passwrod input")
		return ""
	}

	var err error

	r, err = DecryptByString(_s[0], _c[1])
	if err != nil {
		return "Decrypt Error"
	}

	if _c[0] != MD5(r) {
		return "check error"
	}

	fmt.Println("Decrypt to:", r)
	return
}

func MD5(s string) string {
	h := md5.New()
	h.Write([]byte(s))

	return hex.EncodeToString(h.Sum(nil))
}

func EncryptByString(plantText, keystring string) (string, error) {

	hex := md5.New()
	hex.Write([]byte(keystring))
	key := hex.Sum(nil)

	return Encrypt([]byte(plantText), key)
}

//Encrypt 将字符串用AES加密，输出raw base64 字符串
func Encrypt(plantText, key []byte) (planStr string, err error) {

	defer func() {
		if errInterface := recover(); errInterface != nil {
			err = errors.New("数据加密出错")
			// log.Println(errInterface)

		}
	}()

	block, err := aes.NewCipher(key) //选择加密算法
	if err != nil {
		return "", err
	}
	plantText = PKCS7Padding(plantText, block.BlockSize())

	blockModel := cipher.NewCBCEncrypter(block, key)

	ciphertext := make([]byte, len(plantText))

	blockModel.CryptBlocks(ciphertext, plantText)

	cipherBase64 := base64.RawURLEncoding.EncodeToString(ciphertext)

	return cipherBase64, nil
}

//DecryptByString ...
func DecryptByString(cipherBase64, keystring string) (string, error) {
	h := md5.New()
	h.Write([]byte(keystring))
	key := h.Sum(nil)

	return Decrypt(cipherBase64, key)
}

//Decrypt 将base64的字符串解密，再用aes解密
func Decrypt(cipherBase64 string, key []byte) (planStr string, err error) {

	defer func() {
		if errInterface := recover(); errInterface != nil {
			err = errors.New("数据解密出错")
			// log.Println(errInterface)

		}
	}()

	ciphertext, err := base64.RawURLEncoding.DecodeString(cipherBase64)
	if err != nil {
		return "", err
	}

	keyBytes := []byte(key)
	block, err := aes.NewCipher(keyBytes) //选择加密算法
	if err != nil {
		return "", err
	}
	blockModel := cipher.NewCBCDecrypter(block, keyBytes)
	plantText := make([]byte, len(ciphertext))
	blockModel.CryptBlocks(plantText, ciphertext)
	plantText = PKCS7UnPadding(plantText, block.BlockSize())
	return string(plantText), nil
}

//PKCS7Padding 。。。
func PKCS7Padding(plantText []byte, blockSize int) []byte {
	padding := blockSize - len(plantText)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(plantText, padtext...)
}

//PKCS7UnPadding 。。
func PKCS7UnPadding(plantText []byte, blockSize int) []byte {
	length := len(plantText)
	unpadding := int(plantText[length-1])
	return plantText[:(length - unpadding)]
}
