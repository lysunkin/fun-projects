package main

import (
	"fmt"
	"main/donner"
	"main/humanizer"
	"main/t8"
	"os"
	"strconv"

	"github.com/spf13/cobra"
)

func main() {
	var prettyPrint bool
	var rootCmd = &cobra.Command{
		Use:   "program <backup-file> [start-pos]",
		Short: "A tool to process and convert backup files",
		Args:  cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			// File name is required
			fileName := args[0]

			// Parse optional start position
			startPos := 0
			if len(args) >= 2 {
				var err error
				startPos, err = strconv.Atoi(args[1])
				if err != nil || startPos < 0 {
					fmt.Printf("Invalid start position: %s\n", args[1])
					os.Exit(1)
				}
			}

			// Parse the provided file
			backup, err := donner.ParseFile(fileName)
			if err != nil {
				fmt.Printf("Error parsing file '%s': %v\n", fileName, err)
				os.Exit(1)
			}

			// Conditionally pretty print the parsed backup data
			if prettyPrint {
				humanizer.PrettyPrint(backup)
			}

			// Convert the backup data to T8 format and pass the start position
			if err := t8.ToT8(backup, startPos); err != nil {
				fmt.Printf("Error converting to T8 format: %v\n", err)
				os.Exit(1)
			}

			fmt.Println("Conversion to T8 format completed successfully.")
		},
	}

	// Define the -pretty flag
	rootCmd.Flags().BoolVarP(&prettyPrint, "pretty", "p", false, "Enable pretty printing of backup data")

	// Execute the root command
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
