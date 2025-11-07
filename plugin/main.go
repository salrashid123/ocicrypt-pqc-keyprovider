package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/url"
	"os"

	"flag"

	"github.com/containers/ocicrypt/keywrap/keyprovider"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"google.golang.org/protobuf/encoding/protojson"

	pqcwrap "github.com/salrashid123/go-pqc-wrapping"
)

const (
	pqcCryptName = "pqccrypt"
)

var (
	adc       = flag.String("adc", "", "Path to ADC file")
	debugLog  = flag.String("debugLog", "", "Path to debuglog")
	pqcURI    = flag.String("pqcURI", "", "PQC URI")
	pqcKeyURI = flag.String("pqcKeyURI", "", "URI to the private key")
)

type annotationPacket struct {
	KeyUrl     string `json:"key_url"`
	WrappedKey []byte `json:"wrapped_key"`
	WrapType   string `json:"wrap_type"`
}

func main() {

	flag.Parse()

	var err error

	if *debugLog != "" {
		file, err := os.OpenFile(*debugLog, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
		if err != nil {
			log.Printf("error opening log file: %v", err)
		}
		defer file.Close()
		log.SetOutput(file)
		log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
	}

	var input keyprovider.KeyProviderKeyWrapProtocolInput
	err = json.NewDecoder(os.Stdin).Decode(&input)
	if err != nil {
		log.Fatal("decoding input", err)
	}

	switch input.Operation {
	case keyprovider.OpKeyWrap:

		// if the user specified it in command line, set that as the parameter value
		if *pqcURI != "" {
			if len(input.KeyWrapParams.Ec.Parameters) == 0 {
				input.KeyWrapParams.Ec.Parameters = make(map[string][][]byte)
			}
			input.KeyWrapParams.Ec.Parameters[pqcCryptName] = [][]byte{[]byte(*pqcURI)}
		}

		b, err := WrapKey(input)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%s", b)
	case keyprovider.OpKeyUnwrap:

		if *pqcKeyURI != "" {
			if len(input.KeyUnwrapParams.Dc.Parameters) == 0 {
				input.KeyUnwrapParams.Dc.Parameters = make(map[string][][]byte)
			}
			input.KeyUnwrapParams.Dc.Parameters[pqcCryptName] = [][]byte{[]byte(*pqcKeyURI)}
		}

		// if the user specified it in command line, set that as the parameter value
		b, err := UnwrapKey(input)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%s", b)
	default:
		log.Fatalf("Operation %v not recognized", input.Operation)
	}
}

func WrapKey(keyP keyprovider.KeyProviderKeyWrapProtocolInput) ([]byte, error) {

	_, ok := keyP.KeyWrapParams.Ec.Parameters[pqcCryptName]
	if !ok {
		return nil, errors.New("provider must be formatted as provider:pqccrypt:pqc://pq?pub=")
	}

	if len(keyP.KeyWrapParams.Ec.Parameters[pqcCryptName]) == 0 {
		return nil, errors.New("provider must be formatted as provider:pqccrypt:pqc://pq?pub=")
	}

	pqcURI := string(keyP.KeyWrapParams.Ec.Parameters[pqcCryptName][0])

	u, err := url.Parse(string(pqcURI))
	if err != nil {
		return nil, fmt.Errorf("error parsing Provider URL must be  provider:pqccrypt:pqc://pq?pub= %s", pqcURI)
	}

	m, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return nil, fmt.Errorf("error parsing Provider URL: %v", err)
	}

	if m["pub"] == nil {
		return nil, errors.New("error ?pub= value must be set")
	}
	pubPEMData, err := base64.StdEncoding.DecodeString(m["pub"][0])
	if err != nil {
		return nil, fmt.Errorf("error parsing Provider URL: %v", err)
	}

	ctx := context.Background()

	wrapper := pqcwrap.NewWrapper()
	_, err = wrapper.SetConfig(ctx, pqcwrap.WithPublicKey(string(pubPEMData)))
	if err != nil {
		return nil, fmt.Errorf("Error creating wrapper %v", err)
	}

	blobInfo, err := wrapper.Encrypt(ctx, keyP.KeyWrapParams.OptsData)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error encrypting %v\n", err)
		os.Exit(1)
	}

	b, err := protojson.Marshal(blobInfo)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshalling bytes %v\n", err)
		os.Exit(1)
	}

	jsonString, err := json.Marshal(annotationPacket{
		KeyUrl:     pqcURI,
		WrappedKey: b,
		WrapType:   "AES",
	})
	if err != nil {
		return nil, err
	}

	return json.Marshal(keyprovider.KeyProviderKeyWrapProtocolOutput{
		KeyWrapResults: keyprovider.KeyWrapResults{
			Annotation: jsonString,
		},
	})

}

func UnwrapKey(keyP keyprovider.KeyProviderKeyWrapProtocolInput) ([]byte, error) {
	apkt := annotationPacket{}
	err := json.Unmarshal(keyP.KeyUnwrapParams.Annotation, &apkt)
	if err != nil {
		return nil, err
	}

	// load up the keyURL if its in the packet
	pqcURI := apkt.KeyUrl
	ciphertext := apkt.WrappedKey

	// now load it from the parameter; the paramater has the saved value the user specified in the commandline args
	//  the parameter value should take precedent over apkt.KeyUrl
	_, ok := keyP.KeyUnwrapParams.Dc.Parameters[pqcCryptName]
	if ok {
		pqcURI = string(keyP.KeyUnwrapParams.Dc.Parameters[pqcCryptName][0])
	}

	if pqcURI == "" {
		return nil, errors.New("pqcURI cannot be nil")
	}

	ctx := context.Background()

	newBlobInfo := &wrapping.BlobInfo{}
	err = protojson.Unmarshal(ciphertext, newBlobInfo)
	if err != nil {
		return nil, fmt.Errorf("Error unmarshalling %v\n", err)
	}

	u, err := url.Parse(string(pqcURI))
	if err != nil {
		return nil, fmt.Errorf("error parsing prviate URL must be  pqc:// %s", pqcURI)
	}

	wrapper := pqcwrap.NewWrapper()

	if u.Scheme != "pqc" {
		return nil, fmt.Errorf("error scheme must be pqc, got %s", u.Scheme)
	}

	m, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return nil, fmt.Errorf("error parsing Provider URL: %v", err)
	}

	if m["key"] == nil {
		return nil, errors.New("error ?key= value must be set")
	}

	privURI := m["key"][0]

	mk, err := url.Parse(privURI)
	if err != nil {
		return nil, fmt.Errorf("error parsing Provider URL: %v", err)
	}

	var blobInfo []byte
	switch mk.Scheme {
	case "file":
		b, err := os.ReadFile(mk.Path)
		if err != nil {
			return nil, fmt.Errorf("Error reading private key file  %v", err)
		}
		_, err = wrapper.SetConfig(ctx, pqcwrap.WithPrivateKey(string(b)))
		if err != nil {
			return nil, fmt.Errorf("Error creating file wrapper %v", err)
		}

	case "gcpkms":
		ctx := context.Background()

		if *adc != "" {
			os.Setenv("GOOGLE_APPLICATION_CREDENTIALS", *adc)
			//kmsClient, err = kms.NewKeyManagementClient(ctx, option.WithCredentialsFile(*adc))
		}

		_, err = wrapper.SetConfig(ctx, pqcwrap.WithPrivateKey(privURI), pqcwrap.WithKMSKey(true))
		if err != nil {
			return nil, fmt.Errorf("Error creating KMS wrapper %v", err)
		}

	default:
		return nil, fmt.Errorf("scheme must be file:// or gcpkms://, got %s", mk.Scheme)
	}

	blobInfo, err = wrapper.Decrypt(ctx, newBlobInfo)
	if err != nil {
		return nil, fmt.Errorf("Error encrypting %v\n", err)
	}
	return json.Marshal(keyprovider.KeyProviderKeyWrapProtocolOutput{
		KeyUnwrapResults: keyprovider.KeyUnwrapResults{OptsData: blobInfo},
	})
}
