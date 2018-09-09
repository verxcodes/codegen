package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"image/png"
	"io"
	"io/ioutil"
	"os"
	"runtime"

	"github.com/boombuler/barcode"
	"github.com/boombuler/barcode/qr"
	"github.com/davidsonff/qrand"
	uuid "github.com/satori/go.uuid"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"
	jwt "github.com/dgrijalva/jwt-go"
)

const (
	NoError           = iota // No error. Normal exit
	ExitNoPseudo             // Had to use pseudo-random and allow-pseudo flag is set to false
	ExitFSErr                // File system error
	ExitUnexpectedErr        // Unexpected error
	ExitNoOverwrite          // Don't overwrite an existing key!
	ExitECDSAError           // Something went wrong encrypting things
	ExitBarcodeError         // Problem creating the barcode image
	ExitParamError           // Parameter error
)

var config, keyPath, outPath, addText, pseudo string
var img_size int
var genKey bool

// Hopefully, comply with the European Union Directive 2011/62/EU:
var productCode, serialNumber, batchNumber, expirationDate string

type Msg struct {
	Url        string    `json:"URL"`
	UUID       uuid.UUID `json:"UUID"`
	ProdCode   string    `json:"prd"`
	SerNum     string    `json:"ser"`
	Batch      string    `json:"batch"`
	Expiration string    `json:"expires"` // StandardClaims already have exp for ExpiresAt
	OtherInfo  string    `json:"other"`
	jwt.StandardClaims
}

func init() {
	flag.IntVar(&img_size, "image_size", 200, "The pixel size of both the height and width of the image. It's a square.")
	flag.BoolVar(&genKey, "generate_keys", false, "Generates a new key pair. Will not overwrite existing keys.")
	flag.StringVar(&pseudo, "allow_pseudo", "A", "Allow Verx barcode generation with pseudo-random vector. D - Disallow, A - Allow, F-Force")
	flag.StringVar(&addText, "other_info", "", "Additional user-specified text to include in barcode. Keep it simple!")
	flag.StringVar(&config, "config", ".", "The path to the YAML configuration file, verxinit.yml. Defaults to the working directory.")
	flag.StringVar(&productCode, "product_code", "", "The product code of the product.")
	flag.StringVar(&serialNumber, "serial_number", "", "The serial number of the product.")
	flag.StringVar(&batchNumber, "batch_number", "", "The batch number of the product.")
	flag.StringVar(&expirationDate, "expiration_date", "", "The expiration date of the product.")
}

func main() {

	flag.Parse()

	if len(productCode) > 50 { // European Union Directive 2011/62/EU
		fmt.Println("Product code too long!")
		os.Exit(ExitParamError)
	}

	if len(serialNumber) > 20 { // European Union Directive 2011/62/EU
		fmt.Println("Serial number too long!")
		os.Exit(ExitParamError)
	}

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
		rand, err := qrand.Get(56)                                       // Size 56 bytes for 384 bits for P384 curve - 384/8 + 8 = 56
		if _, ok := err.(qrand.PseudoRandomError); ok && pseudo == "D" { // The true random number server is not reachable, so trying to fall back to crypto/rand. Don't allow if pseudo is set to false.
			fmt.Println("Attempt to fall back to pseudo-random generation and allow-pseudo set to false. Exiting...")
			os.Exit(ExitNoPseudo)
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

		prvPem := pem.Block{"PRIVATE KEY", nil, privKey}

		err = pem.Encode(prv, &prvPem)
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

		pubPem := pem.Block{"PUBLIC KEY", nil, pubKey}

		err = pem.Encode(pub, &pubPem)
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

	// Generate barcodes...

	// Get private signing key...

	prv, err := ioutil.ReadFile(privFile)
	if err != nil {
		fmt.Println("Error opening the private key!", err)
		os.Exit(ExitFSErr)
	}

	prvBlk, _ := pem.Decode(prv)

	private_key, err := x509.ParseECPrivateKey(prvBlk.Bytes)
	if err != nil {
		fmt.Println("Error parsing private key!", err)
		os.Exit(ExitECDSAError)
	}

	// Create the JWT token...

	nUUID, err := uuid.NewV4()
	if err != nil {
		fmt.Println("There has been an entropy error. Please try again.")
			panic(err)
		}
	
	msg := Msg{
		viper.GetString("man_url"),
		nUUID,
		productCode,
		serialNumber,
		batchNumber,
		expirationDate,
		addText,
		jwt.StandardClaims{
			Id:     "Verx",
			Issuer: viper.GetString("issuer"),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES384, msg)

	// Sign and get the complete encoded token as a string using the secret

	tokenString, err := token.SignedString(private_key)

	// Create QR code image
	qrCode, err := qr.Encode(tokenString, qr.M, qr.Auto)
	if err != nil {
		fmt.Println("Error creating barcode!", err)
		os.Exit(ExitBarcodeError)
	}

	// Scale the barcode pixel size
	qrCode, err = barcode.Scale(qrCode, img_size, img_size)
	if err != nil {
		fmt.Println("Error creating barcode!", err)
		os.Exit(ExitBarcodeError)
	}

	// create the output file
	file, err := os.Create("qrcode.png")
	if err != nil {
		fmt.Println("Error creating barcode!", err)
		os.Exit(ExitBarcodeError)
	}
	defer file.Close()

	// encode the barcode as png
	png.Encode(file, qrCode)
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
