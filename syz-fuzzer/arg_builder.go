package main

import (
	"bufio"
	"fmt"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/prog"
	"os"
	"strconv"
	"strings"
)

// BuildTable build AddrGenerator
// load addrs without $desc
func BuildTable(target *prog.Target) {
	const AddrPath = "/root/data/addr.txt"
	file, err := os.Open(AddrPath)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	addrGenerator := *prog.GetAddrGeneratorInstance()
	addrCnt := 0

	maxAddr := uint64(0)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()

		// Split the line into key and value based on space
		parts := strings.Split(line, " ")
		if len(parts) != 2 {
			fmt.Println("Invalid line:", line)
			continue
		}

		// Parse the string value to uint64
		value, err := strconv.ParseUint(parts[1], 10, 64)
		if err != nil {
			fmt.Println("Error parsing value for key", parts[0], ":", err)
			continue
		}

		if maxAddr < value {
			maxAddr = value
		}

		addrGenerator.AddrBase[parts[0]] = value
		addrGenerator.AddrCounter[parts[0]] = 0
		addrCnt += 1
	}
	addrGenerator.AddrBase["[UNK]"] = maxAddr + 0x80
	addrGenerator.AddrCounter["[UNK]"] = 0

	log.Logf(0, "Build arg table done: %v", addrCnt)
}
