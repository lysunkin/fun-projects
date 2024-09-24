package humanizer

import (
	"fmt"
	"main/donner"
)

// Constants for gate types
const (
	Slide     = 8
	ThreeFour = 6
	Half      = 4
	Quarter   = 2
	Mute      = 0
)

func convertNote(note int) (string, error) {
	// Ensuring note is within a valid range
	if note < 0 || note > 127 {
		return "", fmt.Errorf("invalid note value: %d", note)
	}
	decode := []string{"C", "C#", "D", "D#", "E", "F", "F#", "G", "G#", "A", "A#", "B"}
	octave := int(note/12) - 1
	n := note % 12
	return fmt.Sprintf("%s%d", decode[n], octave), nil
}

func convertGate(gate int) string {
	switch gate {
	case Slide:
		return "slide"
	case ThreeFour:
		return "3/4"
	case Half:
		return "1/2"
	case Quarter:
		return "1/4"
	default:
		return "mute"
	}
}

// StepStringer allows Steps to implement fmt.Stringer for easy printing
func StepStringer(note, gate int) string {
	noteStr, err := convertNote(note)
	if err != nil {
		// Handle error or return a default value
		return fmt.Sprintf("invalid note: %d", note)
	}
	gateStr := convertGate(gate)
	return fmt.Sprintf("%s-%s", noteStr, gateStr)
}

func PrettyPrint(b donner.Backup) {
	for i, p := range b {
		fmt.Printf("#%d\nTempo: %d, SeqLength: %d\n", i+1, p.Tempo, p.SeqLength+1)
		for _, s := range p.Steps {
			// Using the StepStringer function for clarity and reuse
			fmt.Printf("%s ", StepStringer(s.Note, s.Gate))
		}
		fmt.Println()
	}
}
