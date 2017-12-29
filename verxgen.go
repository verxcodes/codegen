package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"io"
	"math/big"
	"os"
	"runtime"

	"github.com/davidsonff/qrand"
	uuid "github.com/satori/go.uuid"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"
)

const (
	NoError           = iota // No error. Normal exit
	ExitNoPsuedo             // Had to use psuedo-random and allow-psuedo flag is set to false
	ExitFSErr                // File system error
	ExitUnexpectedErr        // Unexpected error
	ExitNoOverwrite          // Don't overwrite an existing key!
	ExitECDSAError           // Something went wrong encrypting things
)

var config, keyPath, outPath, siteURL, jsonmsg string
var count int
var genKey, psuedo bool

type Msg struct {
	Url  String
	UUID uuid.UUID
}

func init() {
	flag.IntVar(&count, "count", 1, "The number of barcodes to generate.")
	flag.BoolVar(&genKey, "generate-key", false, "Generates a new key pair. Will not overwrite existing keys.")
	flag.BoolVar(&psuedo, "allow-psuedo", true, "Allow Verx barcode generation with psuedo-random vector.")
	flag.StringVar(&jsonmsg, "json-msg", "", "Additional user-specified JSON to include in barcode.")
	flag.StringVar(&config, "config", ".", "The path to the YAML configuration file, verxinit.yml. Defaults to the working directory.")
}

func main() {

	flag.Parse()

	viper.SetConfigName("verxinit")
	viper.AddConfigPath(config)

	err := viper.ReadInConfig()
	if err != nil {
		fmt.Println("Cannot read verxinit.yml!", err)
		os.Exit(ExitFSErr)
	}

	// Get the file system info together...
	keyDir := viper.GetString("key_directory")
	privFile := keyDir + string(os.PathSeparator) + viper.GetString("private_key")
	pubFile := keyDir + string(os.PathSeparator) + viper.GetString("public_key")

	// If generating key pair...
	if genKey {

		// Checks to see if everything is ok with the directory and files...
		if _, err := os.Stat(keyDir); os.IsNotExist(err) {

			fmt.Println("Creating key directory:", keyDir)

			err = os.Mkdir(keyDir, 0700) // (drwx------)
			if err != nil {
				fmt.Println("Unable to create key directory:", keyDir)
				os.Exit(ExitFSErr)
			}
		}

		if _, err := os.Stat(privFile); err == nil {
			fmt.Println("Exiting... Will not overwrite an existing key!")
			os.Exit(ExitNoOverwrite)
		}

		if _, err := os.Stat(pubFile); err == nil {
			fmt.Println("Exiting... Will not overwrite an existing key!")
			os.Exit(ExitNoOverwrite)
		}

		// Generate and save the keys...

		// Get random vector for ECDSA...
		rand, err := qrand.Get(56)                                 // Size 56 bytes for 384 bits for P384 curve - 384/8 + 8 = 56
		if _, ok := err.(qrand.PsuedoRandomError); ok && !psuedo { // The true random number server is not reachable, so trying to fall back to crypto/rand. Don't allow if psuedo is set to false.
			fmt.Println("Attempt to fall back to psuedo-random generation and allow-psuedo set to false. Exiting...")
			os.Exit(ExitNoPsuedo)
		} else if err != nil {
			fmt.Println("Unexpected error:", err)
			os.Exit(ExitUnexpectedErr)
		}

		r := bytes.NewReader(rand)

		privKey, pubKey := genPPKeys(r)

		//Save private key...
		prv, err := os.Create(privFile)
		if err != nil {
			fmt.Println("Error creating the private key!", err)
			os.Exit(ExitFSErr)
		}

		if runtime.GOOS != "windows" {
			err = prv.Chmod(0600) // (-rw-------)
			if err != nil {
				fmt.Println("Error setting private key permissions!", err)
				os.Exit(ExitFSErr)
			}
		}

		_, err = prv.Write(privKey)
		if err != nil {
			fmt.Println("Error creating the private key!", err)
			os.Exit(ExitUnexpectedErr)
		}

		err = prv.Close()
		if err != nil {
			fmt.Println("Error creating the private key!", err)
			os.Exit(ExitUnexpectedErr)
		}

		//Save public key...
		pub, err := os.Create(pubFile)
		if err != nil {
			fmt.Println("Error creating the private key!", err)
			os.Exit(ExitFSErr)
		}

		if runtime.GOOS != "windows" {
			err = pub.Chmod(0644) // (-rw-r--r--)
			if err != nil {
				fmt.Println("Error setting public key permissions!", err)
				os.Exit(ExitFSErr)
			}
		}

		_, err = pub.Write(pubKey)
		if err != nil {
			fmt.Println("Error creating the private key!", err)
			os.Exit(ExitUnexpectedErr)
		}

		err = pub.Close()
		if err != nil {
			fmt.Println("Error creating the private key!", err)
			os.Exit(ExitUnexpectedErr)
		}

		fmt.Println("Successfully created the ECDSA key pair.")
		os.Exit(NoError)
	}

	//Generate barcodes...

}

//Credit to Simon Waldherr... https://github.com/SimonWaldherr/golang-examples/blob/master/expert/ppk-crypto.go
func genPPKeys(random io.Reader) (private_key_bytes, public_key_bytes []byte) {

	private_key, err := ecdsa.GenerateKey(elliptic.P384(), random)
	if err != nil {
		fmt.Println(random)
		fmt.Println("ECDSA error generating key:", err)
		os.Exit(ExitECDSAError)
	}

	private_key_bytes, err = x509.MarshalECPrivateKey(private_key)
	if err != nil {
		fmt.Println("ECDSA error marshaling private key:", err)
		os.Exit(ExitECDSAError)
	}

	public_key_bytes, err = x509.MarshalPKIXPublicKey(&private_key.PublicKey)
	if err != nil {
		fmt.Println("ECDSA error marshaling public key:", err)
		os.Exit(ExitECDSAError)
	}

	return private_key_bytes, public_key_bytes
}

func pkSign(hash []byte, private_key_bytes []byte) (r, s *big.Int, err error) {
	zero := big.NewInt(0)
	private_key, err := x509.ParseECPrivateKey(private_key_bytes)
	if err != nil {
		return zero, zero, err
	}

	r, s, err = ecdsa.Sign(rand.Reader, private_key, hash)
	if err != nil {
		return zero, zero, err
	}
	return r, s, nil
}

func pkVerify(hash []byte, public_key_bytes []byte, r *big.Int, s *big.Int) (result bool) {
	public_key, err := x509.ParsePKIXPublicKey(public_key_bytes)
	if err != nil {
		return false
	}

	switch public_key := public_key.(type) {
	case *ecdsa.PublicKey:
		return ecdsa.Verify(public_key, hash, r, s)
	default:
		return false
	}
}
