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

var current = ""

const (
	en_symbol  = "+"
	de_symbol  = "$"
	key_symbol = "="
	times      = 3600
)

func main() {

	fmt.Printf(`
时间加密: %s文本，时间解密时限是 %d 秒
密码加密: %s文本%s密码
加密后，密文自动写入到剪贴板

时间解密: 密文尾部无%s
密码解密: 密文尾部有%s, 复制密文后在尾部%s后输入密码,然后在复制一次
解密内容自动写入到剪贴板
`, en_symbol, times, en_symbol, key_symbol, key_symbol, key_symbol, key_symbol)

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

				//如果剪贴板中的内容是上一次加密或者解密写入的，那么不做任何处理
				if current == content {
					continue
				}

				//加密流程：如果开头是en_symbol号，说明文本需要加密
				if strings.HasPrefix(content, en_symbol) {
					newcontent := EncryptByTime(content[1:])
					err := clipboard.WriteAll(newcontent)
					if err != nil {
						panic(err)
					}
				}
				//解密流程
				//如果开头是de_symbol号，说明内容需要解密
				//并且密文内容结构应该是 de_symbol+32位的md5字符串:密文:原文MD5
				//如果是输入密码的密文，解密内容尾部会有一个 key_symbol 号，如果有，也不执行解密，需要等待输入密码在key_symbol之后
				if strings.HasPrefix(content, de_symbol) && !strings.HasSuffix(content, key_symbol) {
					content = content[1:]             //去掉？号
					cs := strings.Split(content, ":") //用：分割
					if len(cs) != 3 {
						continue
					}
					if cs[0] != MD5(cs[1]) {
						continue
					}

					//如果是输入密码的密文，这时候cs[2]是包含 =密码的，在函数内部会进行处理
					newcontent := DecryptByTime(cs[1], cs[2])
					err := clipboard.WriteAll(newcontent)
					if err != nil {
						panic(err)
					}

				}

			}

		}
	}(ctx)

}

func EncryptByTime(v string) (r string) {

	//用时间作为键
	fmt.Println("开始加密")
	defer fmt.Println("加密完成")
	//默认尾部空字符串，如果是密码模式，会在密文后面加上key_symbol
	ks := ""
	//默认的key是当前时间戳
	k := fmt.Sprintf("%d", time.Now().Unix())

	if _s := strings.Split(v, key_symbol); len(_s) > 1 && _s[len(_s)-1] != "" {
		k = _s[len(_s)-1]
		ks = key_symbol
		v = strings.Join(_s[:len(_s)-1], key_symbol)
	}

	r, err := EncryptByString(v, k)
	if err != nil {
		return err.Error()
	}

	//如果是密码加密模式，会在尾部加上 key_symbol,否则为空字符串
	r = fmt.Sprintf("%s%s:%s:%s%s", de_symbol, MD5(r), r, MD5(v), ks)
	current = r
	fmt.Println("加密并复制为:" + r)
	return
}

func DecryptByTime(v string, check string) (r string) {

	fmt.Println("开始解密")
	defer fmt.Println("解密完成")
	kint := time.Now().Unix()
	var err error

	//用=分割check，无论是不是输入密码的密文，分割后的第一个元素是check字符串
	_s := strings.Split(check, key_symbol)
	check = _s[0]

	//如果分割后，=后面有值，也就是用密码解密模式，否则是用时间解密模式
	if len(_s) > 1 && _s[1] != "" {
		k := _s[1]
		r, err = DecryptByString(v, k)
		if err != nil {
			return "密码错误"
		}

		if check == MD5(r) {
			current = r
			fmt.Println(k, "解密并复制为:", r)
			return
		}

		return "内容验证错误"
	} else {
		for i := 0; i < times; i++ {

			k := fmt.Sprintf("%d", kint-int64(i))
			r, err = DecryptByString(v, k)
			if err != nil {
				continue
			}

			if check == MD5(r) {
				current = r
				fmt.Println(i, "解密并复制为:", r)
				return
			}
		}
	}

	return "overtime"
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
