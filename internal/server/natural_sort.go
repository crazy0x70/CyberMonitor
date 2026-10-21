package server

import (
	"unicode"
)

// naturalCompare 按「自然顺序」比较节点展示名，返回 -1 / 0 / 1。
//
// 规则：
//  1. 逐字符比较，忽略大小写（hk 与 HK 视为同序）；
//  2. 连续数字段按数值比较，因此 hk2 < hk10、v1.2 < v1.10；
//  3. 数值相等时忽略前导零（v07 与 v7 视为同序），继续比较后续字符；
//  4. 完全同序返回 0，由调用方回退到原始字节序与 NodeID 保证排序稳定。
//
// 非 ASCII 字符（中文、西里尔文等）同样经 unicode.ToLower 折叠后按码位比较，
// 结果确定可复现，但不对应任何语言的字母序——用户编号命名才是这里要修的场景。
func naturalCompare(left, right string) int {
	leftRunes := []rune(left)
	rightRunes := []rune(right)
	i, j := 0, 0
	for i < len(leftRunes) && j < len(rightRunes) {
		leftRune := leftRunes[i]
		rightRune := rightRunes[j]
		if isASCIIDigit(leftRune) && isASCIIDigit(rightRune) {
			leftStart, rightStart := i, j
			for i < len(leftRunes) && isASCIIDigit(leftRunes[i]) {
				i++
			}
			for j < len(rightRunes) && isASCIIDigit(rightRunes[j]) {
				j++
			}
			leftNumber := trimLeadingZeros(leftRunes[leftStart:i])
			rightNumber := trimLeadingZeros(rightRunes[rightStart:j])
			// 去掉前导零后位数多的数值更大，位数相同再逐位比较。
			if len(leftNumber) != len(rightNumber) {
				return compareInts(len(leftNumber), len(rightNumber))
			}
			for index := range leftNumber {
				if leftNumber[index] != rightNumber[index] {
					return compareInts(int(leftNumber[index]), int(rightNumber[index]))
				}
			}
			continue
		}
		leftLower := unicode.ToLower(leftRune)
		rightLower := unicode.ToLower(rightRune)
		if leftLower != rightLower {
			return compareInts(int(leftLower), int(rightLower))
		}
		i++
		j++
	}
	// 前缀相同时更短的名字排前面（hk < hk2）。
	switch {
	case i < len(leftRunes):
		return 1
	case j < len(rightRunes):
		return -1
	}
	return 0
}

// naturalLess 是 naturalCompare 的布尔包装，供 sort.Slice 使用。
func naturalLess(left, right string) bool {
	return naturalCompare(left, right) < 0
}

func compareInts(left, right int) int {
	switch {
	case left < right:
		return -1
	case left > right:
		return 1
	}
	return 0
}

func isASCIIDigit(value rune) bool {
	return value >= '0' && value <= '9'
}

func trimLeadingZeros(value []rune) []rune {
	index := 0
	for index < len(value)-1 && value[index] == '0' {
		index++
	}
	return value[index:]
}
