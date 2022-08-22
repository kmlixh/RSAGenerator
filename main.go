package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"time"
)

func RSAGenKey(bits int, namePrefixs ...string) error {
	namePrefix := ""
	if len(namePrefixs) > 0 {
		namePrefix = namePrefixs[0]
	}
	/*
		生成私钥
	*/
	//1、使用RSA中的GenerateKey方法生成私钥
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return err
	}
	//2、通过X509标准将得到的RAS私钥序列化为：ASN.1 的DER编码字符串
	privateStream := x509.MarshalPKCS1PrivateKey(privateKey)
	//3、将私钥字符串设置到pem格式块中
	block1 := pem.Block{
		Type:  "private key",
		Bytes: privateStream,
	}
	//4、通过pem将设置的数据进行编码，并写入磁盘文件
	fPrivate, err := os.Create(namePrefix + "privateKey.pem")
	if err != nil {
		return err
	}
	defer fPrivate.Close()
	err = pem.Encode(fPrivate, &block1)
	if err != nil {
		return err
	}

	/*
		生成公钥
	*/
	publicKey := privateKey.PublicKey
	publicStream, err := x509.MarshalPKIXPublicKey(&publicKey)
	//publicStream:=x509.MarshalPKCS1PublicKey(&publicKey)
	block2 := pem.Block{
		Type:  "public key",
		Bytes: publicStream,
	}
	fPublic, err := os.Create(namePrefix + "publicKey.pem")
	if err != nil {
		return err
	}
	defer fPublic.Close()
	pem.Encode(fPublic, &block2)
	return nil
}

//对数据进行加密操作
func EncryptByRSA(src []byte, publicKeys []byte) (res []byte, err error) {

	// 使用X509将解码之后的数据 解析出来
	//x509.MarshalPKCS1PublicKey(block):解析之后无法用，所以采用以下方法：ParsePKIXPublicKey
	keyInit, err := x509.ParsePKIXPublicKey(publicKeys) //对应于生成秘钥的x509.MarshalPKIXPublicKey(&publicKey)
	//keyInit1,err:=x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return
	}
	//4.使用公钥加密数据
	pubKey := keyInit.(*rsa.PublicKey)
	res, err = rsa.EncryptPKCS1v15(rand.Reader, pubKey, src)
	return
}

//对数据进行加密操作
func EncryptByRSAPath(src []byte, path string) (res []byte, err error) {
	//1.获取秘钥（从本地磁盘读取）
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	fileInfo, _ := f.Stat()
	b := make([]byte, fileInfo.Size())
	f.Read(b)
	// 2、将得到的字符串解码
	block, _ := pem.Decode(b)
	return EncryptByRSA(src, block.Bytes)
}

//对数据进行解密操作
func DecryptByKeyPath(src []byte, path string) (res []byte, err error) {
	//1.获取秘钥（从本地磁盘读取）
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	fileInfo, _ := f.Stat()
	b := make([]byte, fileInfo.Size())
	f.Read(b)
	block, _ := pem.Decode(b) //解码
	return DecryptData(src, block.Bytes)
}
func DecryptData(data []byte, privateKeys []byte) (res []byte, err error) {
	privateKey, err := x509.ParsePKCS1PrivateKey(privateKeys) //还原数据
	res, err = rsa.DecryptPKCS1v15(rand.Reader, privateKey, data)
	return
}

var mode = flag.String("mode", "gen", "mode的可取值：gen-生成密钥，encode，解析内容;encodeFile,decode,decodeFile")
var bits = flag.Int("bits", 4096, "密钥位数，2048或者4096，默认4096")
var input = flag.String("in", "input.txt", "待处理的文件名称或内容")
var keyPrefix = flag.String("prefix", "", "密钥前缀")
var outputPath = flag.String("out", "output.txt", "输出文件名称")
var privateKeyPath = flag.String("private", "privateKey.pem", "私钥路径")
var publicKeyPath = flag.String("public", "publicKey.pem", "公钥地址")

func main() {
	flag.Parse()
	fmt.Println("mode:", *mode)
	switch *mode {
	case "gen":
		prefix := *keyPrefix
		if prefix == "" {
			t := time.Now()
			prefix = t.Format("20060102150405") + "-"
		}
		err := RSAGenKey(*bits, prefix)
		if err != nil {
			fmt.Println("generate occurs errors", err)
		} else {
			fmt.Println("密钥生成成功")
		}

	case "encode":
		b := []byte(*input)
		results, err := EncryptByRSAPath(b, *publicKeyPath)
		if err != nil {
			panic(err)
		} else {
			fmt.Println(base64.URLEncoding.EncodeToString(results))
		}
	case "decode":
		b, er := base64.URLEncoding.DecodeString(*input)
		if er != nil {
			panic(er)
		}
		results, err := DecryptByKeyPath(b, *privateKeyPath)
		if err != nil {
			panic(err)
		} else {
			fmt.Println(string(results))
		}
	case "encodeFile":
		f, err := os.Open(*input)
		if err != nil {
			return
		}
		defer f.Close()
		fileInfo, _ := f.Stat()
		b := make([]byte, fileInfo.Size())
		f.Read(b)
		results, err := EncryptByRSAPath(b, *publicKeyPath)
		ff, er := os.Create(*outputPath)
		if er != nil {
			panic(er)
		}
		_, er = ff.WriteString(base64.URLEncoding.EncodeToString(results))
		if er != nil {
			panic(er)
		} else {
			fmt.Println("加密成功")
		}
	case "decodeFile":
		f, err := os.Open(*input)
		if err != nil {
			return
		}
		defer f.Close()
		fileInfo, _ := f.Stat()
		b := make([]byte, fileInfo.Size())
		f.Read(b)
		bb, er := base64.URLEncoding.DecodeString(string(b))
		if er != nil {
			panic(er)
		}
		results, err := DecryptByKeyPath(bb, *privateKeyPath)
		ff, er := os.Create(*outputPath)
		if er != nil {
			panic(er)
		}
		_, er = ff.Write(results)
		if er != nil {
			panic(er)
		} else {
			fmt.Println("解密成功")
		}
	}
}
