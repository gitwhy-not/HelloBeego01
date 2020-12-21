package main

import (
	"BcAddressCode/base58"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"golang.org/x/crypto/ripemd160"
)

const VERSION = 0x00

func main() {
	fmt.Println("hello world")
	//第一步 ： 生成私钥和公钥
	curve := elliptic.P256()
	//x y 可以组成公钥
	_, x, y, err := elliptic.GenerateKey(curve, rand.Reader)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	//将X和Y组成公钥，转换为[]byte类型
	//公钥：x坐标 + y坐标
	//pubKey := append(x.Bytes(), y.Bytes()...)

	pubKey := elliptic.Marshal(curve, x, y)
	fmt.Println(pubKey)
	fmt.Println(len(pubKey))

	//第二部， hash计算
	sha256Hash := sha256.New()
	sha256Hash.Write(pubKey)
	pubHash256 := sha256Hash.Sum(nil)
	//ripemd160
	ripemd := ripemd160.New()
	ripemd.Write(pubHash256)
	pubRipemd160 := ripemd.Sum(nil)

	//第三步， 添加版本号
	versionPubRipemd160 := append([]byte{0x00}, pubRipemd160...)

	//第四步， 计算校验位
	//a:sha256
	sha256Hash.Reset() //重置
	sha256Hash.Write(versionPubRipemd160)
	hash1 := sha256Hash.Sum(nil)
	//b: sha256
	sha256Hash.Reset()
	sha256Hash.Write(hash1)
	hash2 := sha256Hash.Sum(nil)
	//c:取前4个字节
	check := hash2[0:4]
	fmt.Println(check)

	//第五步，拼接校验位
	addBytes := append(versionPubRipemd160, check...)
	fmt.Println("地址：", addBytes)

	//第六步： 对地址进行base58编码
	address := base58.Encode(addBytes)
	fmt.Println("生成的新的比特币地址：", address)
}


func GenerateKey(curve elliptic.Curve) (*ecdsa.PrivateKey, error){
	return ecdsa.GenerateKey(curve, rand.Reader)
}

func GetUnCompressPub(curve elliptic.Curve, pri *ecdsa.PrivateKey) []byte {
	 return elliptic.Marshal(curve, pri.X, pri.Y)
}

func SHA256Hash(msg []byte) []byte {
	sha256Hash := sha256.New()
	sha256Hash.Write(msg)
	return sha256Hash.Sum(nil)
}

func Ripemd160Hash(msg []byte) []byte{
	ripemd := ripemd160.New()
	ripemd.Write(msg)
	return ripemd.Sum(nil)
}

func GetAddress() string {
	curve := elliptic.P256()
	pri, _ := GenerateKey(curve)
	pub := GetUnCompressPub(curve, pri)
    //第一次sha256
	hash256 := SHA256Hash(pub)
    //ripemd160
	ripemd := Ripemd160Hash(hash256)
	//version
	versionRipemd := append([]byte{VERSION}, ripemd... )
   //第二次
	hash1 := SHA256Hash(versionRipemd)
	hash2 := SHA256Hash(hash1)

	check := hash2[:4]

	add := append(versionRipemd,check...)
	return base58.Encode(add)
}

func CheckAdd(add string) bool {
	//解码
	deAddBytes := base58.Decode(add)
	//截取最后四位
	deCheck := deAddBytes[len(deAddBytes)-4]
	versionRipemd160 := deAddBytes[:len(deAddBytes)-4]
	//第一次hash
	sha256Hash := sha256.New()
	sha256Hash.Write(versionRipemd160)
	hash1 := sha256Hash.Sum(nil)
	//第二次hash
	sha256Hash.Reset()
	sha256Hash.Write(hash1)
	hash2 := sha256Hash.Sum(nil)
	//截取前四位进行校验
	check := hash2[:4]
	//验证
	if string(deCheck) == string(check) {
		fmt.Println("地址验证成功！")
} else {
        fmt.Println("地址验证失败！")
}
     return false
}