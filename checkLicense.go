// Author me@bytejedi.com
// 使用椭圆曲线数字签名算法，把机器的SN当作随机数生成压缩公钥(license)，校验license

package license

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"io"
	"log"
	"math/big"

	"encoding/hex"
	"golang.org/x/crypto/ripemd160"
	"os"
)

const (
	version            = byte(0x00)
	licenseChecksumLen = 4
)

// 配置文件中的授权码
var LicenseKey string

// 自定义base58的字母表
var b58Alphabet = []byte("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")

// License密钥对
type License struct {
	PrivateKey ecdsa.PrivateKey
	PublicKey  []byte
}

// newLicense 创建并返回一个License
func newLicense(sn io.Reader) *License {
	private, public := newKeyPair(sn)
	license := License{private, public}

	return &license
}

// getLicenseKey 通过公钥生成可读的授权码并返回
func (w License) getLicenseKey() []byte {
	pubKeyHash := hashPubKey(w.PublicKey)

	versionedPayload := append([]byte{version}, pubKeyHash...)
	checksum := checksum(versionedPayload)

	fullPayload := append(versionedPayload, checksum...)
	licenseKey := base58Encode(fullPayload)

	return licenseKey
}

// hashPubKey 公钥哈希
func hashPubKey(pubKey []byte) []byte {
	publicSHA256 := sha256.Sum256(pubKey)

	RIPEMD160Hasher := ripemd160.New()
	_, err := RIPEMD160Hasher.Write(publicSHA256[:])
	if err != nil {
		log.Panic(err)
	}
	publicRIPEMD160 := RIPEMD160Hasher.Sum(nil)

	return publicRIPEMD160
}

// Checksum 两次SHA256
func checksum(payload []byte) []byte {
	firstSHA := sha256.Sum256(payload)
	secondSHA := sha256.Sum256(firstSHA[:])

	return secondSHA[:licenseChecksumLen]
}

// newKeyPair 创建并返回一个私钥公钥
func newKeyPair(sn io.Reader) (ecdsa.PrivateKey, []byte) {
	curve := elliptic.P256()
	private, err := ecdsa.GenerateKey(curve, sn)
	if err != nil {
		log.Panic(err)
	}
	pubKey := append(private.PublicKey.X.Bytes(), private.PublicKey.Y.Bytes()...)

	return *private, pubKey
}

// base58Encode 将[]byte编码为base58
func base58Encode(input []byte) []byte {
	var result []byte

	x := big.NewInt(0).SetBytes(input)

	base := big.NewInt(int64(len(b58Alphabet)))
	zero := big.NewInt(0)
	mod := &big.Int{}

	for x.Cmp(zero) != 0 {
		x.DivMod(x, base, mod)
		result = append(result, b58Alphabet[mod.Int64()])
	}

	reverseBytes(result)
	for b := range input {
		if b == 0x00 {
			result = append([]byte{b58Alphabet[0]}, result...)
		} else {
			break
		}
	}

	return result
}

// reverseBytes 反转[]byte
func reverseBytes(data []byte) {
	for i, j := 0, len(data)-1; i < j; i, j = i+1, j-1 {
		data[i], data[j] = data[j], data[i]
	}
}

// Check license校验
func Check() {
	sn, err := getMachineSN()
	if err != nil {
		zlog.Error(err)
		os.Exit(0)
	}

	hexByte, _ := hex.DecodeString(sn)
	l := newLicense(bytes.NewReader(hexByte))
	licenseKey := l.getLicenseKey()

	if LicenseKey != string(licenseKey) {
		zlog.Error("无效的授权码")
		os.Exit(0)
	}
}
