package t8

import (
	"fmt"
	"main/donner"
	"os"
	"path/filepath"
)

const (
	restoreDir  = "RESTORE"
	dirPattern  = "PTN_BANK%02d"
	filePattern = "T8_BASS_PTN%02d_%02d.PRM"
	headerTpl   = "LENGTH\t= %d\nTRIPLET\t= 0\n"
	lineTpl     = "STEP %d\t= STATE=%d NOTE=%d ACCENT=%d SLIDE=%d\n"

	STATE_ON        = 1
	STATE_MUTE      = 2
	SLIDE_ON        = 1
	SLIDE_OFF       = 0
	ACCENT_ON       = 1
	ACCENT_OFF      = 0
	stepsPerPattern = 32 // Maximum number of steps in a pattern
)

func ToT8(b donner.Backup, startPos int) error {
	// Ensure the RESTORE directory exists
	if err := os.MkdirAll(restoreDir, 0755); err != nil {
		return fmt.Errorf("failed to create restore directory: %w", err)
	}

	// Iterate through pattern banks (4 banks) and patterns (16 per bank)
	for i := 0; i < 4; i++ {
		dirPath := filepath.Join(restoreDir, fmt.Sprintf(dirPattern, i+1))
		if err := os.MkdirAll(dirPath, 0755); err != nil {
			return fmt.Errorf("failed to create bank directory: %w", err)
		}

		for j := 0; j < 16; j++ {
			// Check if the backup has enough patterns to process
			backupIndex := i*16 + j + startPos
			if backupIndex >= len(b) {
				return nil
			}

			// Generate file path and create the file
			filePath := filepath.Join(dirPath, fmt.Sprintf(filePattern, i+1, j+1))
			if err := writePatternFile(filePath, b[backupIndex]); err != nil {
				return fmt.Errorf("failed to write pattern file %s: %w", filePath, err)
			}
		}
	}
	return nil
}

// writePatternFile creates a file for a pattern and writes header and step data
func writePatternFile(path string, pattern donner.Pattern) error {
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0755)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	// Write the header to the file
	if _, err := file.WriteString(fmt.Sprintf(headerTpl, pattern.SeqLength+1)); err != nil {
		return fmt.Errorf("failed to write header: %w", err)
	}

	// Write the steps to the file
	if err := writeSteps(file, pattern.Steps); err != nil {
		return fmt.Errorf("failed to write steps: %w", err)
	}

	return nil
}

// getState returns the state based on the gate value
func getState(s donner.Step) int {
	if s.Gate == 0 {
		return STATE_MUTE
	}
	return STATE_ON
}

// getSlide returns the slide status based on the gate value
func getSlide(s donner.Step) int {
	if s.Gate == 8 {
		return SLIDE_ON
	}
	return SLIDE_OFF
}

// writeSteps writes the steps to the file
func writeSteps(f *os.File, steps []donner.Step) error {
	// Write the actual steps present in the pattern
	for i, s := range steps {
		if _, err := f.WriteString(fmt.Sprintf(lineTpl, i+1, getState(s), s.Note, ACCENT_OFF, getSlide(s))); err != nil {
			return fmt.Errorf("failed to write step %d: %w", i+1, err)
		}
	}

	// Fill the remaining steps with mutes if fewer than 32 steps
	for i := len(steps); i < stepsPerPattern; i++ {
		if _, err := f.WriteString(fmt.Sprintf(lineTpl, i+1, STATE_MUTE, 36, ACCENT_OFF, SLIDE_OFF)); err != nil {
			return fmt.Errorf("failed to write mute step %d: %w", i+1, err)
		}
	}

	return nil
}
