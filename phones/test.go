// You can edit this code!
// Click here and start typing.
// To execute Go code, please declare a func main() in a package "main"
// Image of a telephone's keypad: https://upload.wikimedia.org/wikipedia/commons/thumb/7/73/Telephone-keypad2.svg/2880px-Telephone-keypad2.svg.png

// Problem: Given phone number, output all possible letter values or "words".
// Example:
// Input: 123-000
// Output:
// 1ad-000
// 1ae-000
// 1af-000
// 1bd-000
// 1be-000
// 1bf-000
// 1cd-000
// 1ce-000
// 1cf-000
//

// 1: 1
// 2: abc
// 3: def
// 4: ghi
// 5: jkl
// 6: mno
// 7: pqrs
// 8: tuv
// 9: wxyz
// 0: 0
//
// Other input examples:
// 425.123.5000
// (+1) 505-445-9830

package main

import "fmt"

func decode(phoneNumber string) []string {
	decodeTable := map[string][]string{
		"2": {"a", "b", "c"},
		"3": {"d", "e", "f"},
		"4": {"g", "h", "i"},
		"5": {"j", "k", "l"},
		"6": {"m", "n", "o"},
		"7": {"p", "q", "r", "s"},
		"8": {"t", "u", "v"},
		"9": {"w", "x", "y", "z"},
	}

	result := []string{""}

	for _, ch := range phoneNumber {
		if val, ok := decodeTable[string(ch)]; ok {
			var temp []string
			for _, elem := range result {
				for _, letter := range val {
					temp = append(temp, elem+string(letter))
				}
			}
			result = temp
		} else {
			for i, elem := range result {
				result[i] = elem + string(ch)
			}
		}
	}

	return result
}

func main() {
	for _, val := range decode("(737)333-5066") {
		fmt.Println(val)
	}
}
