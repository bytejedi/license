// Author me@bytejedi.com
// 调用并解析Linux命令：dmidecode
// SMBIOS详细文档 https://www.dmtf.org/sites/default/files/standards/documents/DSP0134_3.1.1.pdf

package license

import (
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

const (
	// dmidecode命令行
	DMIDecodeBinary = "dmidecode"
)

type DMI struct {
	Data   map[string]map[string]string // 命令行的输出内容
	Binary string                       // 命令行
}

func newDMI() *DMI {
	return &DMI{
		Data:   make(map[string]map[string]string),
		Binary: DMIDecodeBinary,
	}
}

// run 试图找到一个有效的`dmidecode`命令，并执行它，解析它输出的任何数据。
func (d *DMI) run() error {
	bin, err := d.findBin(d.Binary)
	if err != nil {
		return err
	}

	output, err := d.execDmidecode(bin)
	if err != nil {
		return err
	}

	return d.parseDmidecode(output)
}

// findBin 尝试从PATH中找到一个有效的binary.
func (d *DMI) findBin(binary string) (string, error) {
	locations := []string{"/sbin", "/usr/sbin", "/usr/local/sbin"}

	for _, path := range locations {
		lookup := path + "/" + binary

		fileInfo, err := os.Stat(path + "/" + binary)
		if err != nil {
			continue
		}

		if !fileInfo.IsDir() {
			return lookup, nil
		}
	}

	return "", fmt.Errorf("Unable to find the '%v' binary\n", binary)
}

// ExecDmiDecode 尝试执行binary, 捕获并返回它的输出（或者返回错误）
func (d *DMI) execDmidecode(binary string) (string, error) {
	cmd := exec.Command(binary)

	output, err := cmd.Output()
	if err != nil {
		return "", err
	}

	return string(output), nil
}

// ParseDmiDecode 尝试解析dmidecode的所有输出，并将匹配的内容放到d.Data中
func (d *DMI) parseDmidecode(output string) error {
	// 每条内容用双换行符分隔
	splitOutput := strings.Split(output, "\n\n")

	for _, record := range splitOutput {
		recordElements := strings.Split(record, "\n")

		// 少于3行的条目是不完整的/不活动的；跳过它们
		if len(recordElements) < 3 {
			continue
		}

		handleRegex, _ := regexp.Compile("^Handle\\s+(.+),\\s+DMI\\s+type\\s+(\\d+),\\s+(\\d+)\\s+bytes$")
		handleData := handleRegex.FindStringSubmatch(recordElements[0])

		if len(handleData) == 0 {
			continue
		}

		dmiHandle := handleData[1]

		d.Data[dmiHandle] = make(map[string]string)
		d.Data[dmiHandle]["DMIType"] = handleData[2]
		d.Data[dmiHandle]["DMISize"] = handleData[3]

		// 第二行 == name
		d.Data[dmiHandle]["DMIName"] = recordElements[1]

		inBlockElement := ""
		inBlockList := ""

		// 循环内容的其余部分，收集value
		for i := 2; i < len(recordElements); i++ {
			// 检查是否在一个 \t\t 块
			if inBlockElement != "" {
				inBlockRegex, _ := regexp.Compile("^\\t\\t(.+)$")
				inBlockData := inBlockRegex.FindStringSubmatch(recordElements[i])

				if len(inBlockData) > 0 {
					if len(inBlockList) == 0 {
						inBlockList = inBlockData[1]
					} else {
						inBlockList = inBlockList + "\t\t" + inBlockData[1]
					}
					d.Data[dmiHandle][inBlockElement] = inBlockList
					continue
				} else {
					// 我们不在 \t\t 块; 重置, 继续解析
					inBlockElement = ""
				}
			}

			recordRegex, _ := regexp.Compile("\\t(.+):\\s+(.+)$")
			recordData := recordRegex.FindStringSubmatch(recordElements[i])

			// 此行内容是否包含 handle identifier, type, size?
			if len(recordData) > 0 {
				d.Data[dmiHandle][recordData[1]] = recordData[2]
				continue
			}

			// 没有匹配到常规条目, 是数组数据?
			recordRegex2, _ := regexp.Compile("\\t(.+):$")
			recordData2 := recordRegex2.FindStringSubmatch(recordElements[i])

			if len(recordData2) > 0 {
				// 这是一条数组数据
				inBlockElement = recordData2[1]
				continue
			}
		}
	}

	if len(d.Data) == 0 {
		return fmt.Errorf("Unable to parse 'dmidecode' output\n")
	}

	return nil
}

// genericSearchBy 在d.Data中查询param value
func (d *DMI) genericSearchBy(param, value string) (map[string]string, error) {
	if len(d.Data) == 0 {
		return nil, fmt.Errorf("DMI data is empty; make sure to .run() first")
	}

	for _, v := range d.Data {
		if v[param] == value {
			return v, nil
		}
	}

	return make(map[string]string), nil
}

// searchByName 通过指定的name在d.Data中查询对应的DMI记录
func (d *DMI) searchByName(name string) (map[string]string, error) {
	return d.genericSearchBy("DMIName", name)
}

// searchByType 通过指定的type在d.Data中查询对应的DMI记录
func (d *DMI) searchByType(id int) (map[string]string, error) {
	return d.genericSearchBy("DMIType", strconv.Itoa(id))
}
