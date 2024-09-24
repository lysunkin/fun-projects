package donner

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
)

type Step struct {
	Note     int    `json:"note"`     // Note number
	Tap      int    `json:"tap"`      // Step number in a sequence
	Gate     int    `json:"val"`      // 0 = rest/mute, 2 = 25%, 4 = 50%, 8 = 100%
	Velocity int    `json:"velocity"` // Velocity can be used for dynamic patterns
	Ptn      string `json:"ptn"`      // Optional
}

type Pattern struct {
	Tempo     int    `json:"tempo"`
	SeqLength int    `json:"seqLength"`
	Transpose int    `json:"transpose"`
	Steps     []Step `json:"list"`
}

type Backup []Pattern

// ParseFile parses the given file and returns a Backup struct.
// Errors are returned to the caller for better error handling.
func ParseFile(fileName string) (Backup, error) {
	jsonFile, err := os.Open(fileName)
	if err != nil {
		return nil, fmt.Errorf("error opening file: %v", err)
	}
	defer jsonFile.Close()

	byteValue, err := io.ReadAll(jsonFile)
	if err != nil {
		return nil, fmt.Errorf("error reading file: %v", err)
	}

	var backup Backup
	if err := json.Unmarshal(byteValue, &backup); err != nil {
		return nil, fmt.Errorf("error unmarshalling JSON: %v", err)
	}

	// Sort steps by Tap for each pattern in place
	for i := range backup {
		sort.Slice(backup[i].Steps, func(a, b int) bool {
			return backup[i].Steps[a].Tap < backup[i].Steps[b].Tap
		})
	}

	return backup, nil
}
