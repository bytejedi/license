// Author me@bytejedi.com
// 生成机器的唯一的SN序列号

package license

import (
	"bytes"
	"errors"
	"os/user"
	"strings"
)

// 获得主机的序列号
func getMachineSN() (string, error) {
	if ok, err := isRoot(); !ok {
		return "", err
	}

	var systemUUID, cpuID string
	dmi := newDMI()

	if err := dmi.run(); err != nil {
		return "", errors.New("Unable to get machine's information.\n")
	}
	// 通过System Information的DMIType：1来查询系统的UUID
	systemByNameData, err := dmi.searchByType(1)
	if err != nil {
		return "", errors.New("Unable to get machine's information.\n")
	}
	for k, v := range systemByNameData {
		if k == "UUID" {
			systemUUID = v
		}
	}
	// 通过Processor Information的DMIType：4来查询CPU的ID
	cpuByNameData, err := dmi.searchByType(4)
	if err != nil {
		return "", errors.New("Unable to get machine's information.\n")
	}
	for k, v := range cpuByNameData {
		if k == "ID" {
			cpuID = v
		}
	}
	if systemUUID != "" && cpuID != "" {
		sn, err := chaos(systemUUID, cpuID)
		if err != nil {
			return "", err
		}
		return sn, nil
	}
	return "", errors.New("Get machine's information failed.\n")
}

// 混淆cpuID和systemUUID，返回机器的80长度的16进制的SN字符串
func chaos(systemUUID, cpuID string) (string, error) {
	var tmpByteSlice [][]byte
	var tmpByte []byte
	cpuID = strings.Replace(cpuID, " ", "", -1)
	systemUUID = strings.Replace(systemUUID, "-", "", -1)

	cpuIDByte := []byte(cpuID)
	systemUUIDByte := []byte(systemUUID)

	tmpByteSlice = append(tmpByteSlice, cpuIDByte[0:5], cpuIDByte[11:], cpuIDByte[9:11], cpuIDByte[5:9])
	tmpByteSlice = append(tmpByteSlice, systemUUIDByte[7:15], systemUUIDByte[:7], systemUUIDByte[24:], systemUUIDByte[15:24])
	tmpByte = bytes.Join(tmpByteSlice, []byte(""))

	tmpByteSlice = append(tmpByteSlice, tmpByte[45:], tmpByte[18:22], tmpByte[:5], tmpByte[43:45], tmpByte[31:38], tmpByte[25:31], tmpByte[38:43])
	if sn := string(bytes.Join(tmpByteSlice, []byte(""))); len(sn) == 80 {
		return string(bytes.Join(tmpByteSlice, []byte(""))), nil
	}
	return "", errors.New("Generate machine's SN failed.\n")
}

// 获取当前运行本程序的用户是否为root。是，返回true，不是，返回false
func isRoot() (bool, error) {
	if u, err := user.Current(); err == nil {
		if u.Username == "root" {
			return true, nil
		}
		return false, errors.New("需要root权限")
	}
	return false, errors.New("获取当前用户失败")
}
