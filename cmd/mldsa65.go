package cmd

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/spf13/cobra"
)

var (
	mldsa65Seed string
	mldsa65Cmd  = &cobra.Command{
		Use:   "mldsa65",
		Short: "Generate key pair for ML-DSA-65 post-quantum signature (REALITY)",
		Run: func(cmd *cobra.Command, args []string) {
			if err := genMLDSA65(); err != nil {
				fmt.Println(err)
			}
		},
	}
)

func init() {
	mldsa65Cmd.PersistentFlags().StringVarP(&mldsa65Seed, "input", "i", "", "Input seed (base64.RawURLEncoding)")
	rootCmd.AddCommand(mldsa65Cmd)
}

func genMLDSA65() error {
	var seed [32]byte

	if mldsa65Seed == "" {
		if _, err := rand.Read(seed[:]); err != nil {
			return err
		}
	} else {
		s, err := base64.RawURLEncoding.DecodeString(mldsa65Seed)
		if err != nil {
			return err
		}
		if len(s) != 32 {
			return errors.New("invalid length of ML-DSA-65 seed")
		}
		seed = [32]byte(s)
	}

	pub, _ := mldsa65.NewKeyFromSeed(&seed)

	output := fmt.Sprintf("Seed: %v\nVerify: %v",
		base64.RawURLEncoding.EncodeToString(seed[:]),
		base64.RawURLEncoding.EncodeToString(pub.Bytes()))
	fmt.Println(output)

	return nil
}
