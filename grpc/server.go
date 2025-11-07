package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"

	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/containers/ocicrypt/keywrap/keyprovider"
	keyproviderpb "github.com/containers/ocicrypt/utils/keyprovider"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	pqcwrap "github.com/salrashid123/go-pqc-wrapping"
)

var (
	wrapper   *pqcwrap.PQCWrapper
	grpcport  = flag.String("grpcport", ":50051", "grpcport")
	adc       = flag.String("adc", "", "Path to ADC file")
	pqcURI    = flag.String("pqcURI", "", "PQC URI")
	pqcKeyURI = flag.String("pqcKeyURI", "", "URI to the private key")
)

const (
	pqcCryptName = "grpc-keyprovider"
)

type server struct {
	keyproviderpb.UnimplementedKeyProviderServiceServer
}

type annotationPacket struct {
	KeyUrl     string `json:"key_url"`
	WrappedKey []byte `json:"wrapped_key"`
	WrapType   string `json:"wrap_type"`
}

func (*server) WrapKey(ctx context.Context, request *keyproviderpb.KeyProviderKeyWrapProtocolInput) (*keyproviderpb.KeyProviderKeyWrapProtocolOutput, error) {
	log.Println("got WrapKey")
	var keyP keyprovider.KeyProviderKeyWrapProtocolInput
	err := json.Unmarshal(request.KeyProviderKeyWrapProtocolInput, &keyP)
	if err != nil {
		return nil, err
	}

	// if the user specified it in command line, set that as the parameter value

	if *pqcURI != "" {
		if len(keyP.KeyWrapParams.Ec.Parameters) == 0 {
			keyP.KeyWrapParams.Ec.Parameters = make(map[string][][]byte)
		}
		keyP.KeyWrapParams.Ec.Parameters[pqcCryptName] = [][]byte{[]byte(*pqcURI)}
	}

	_, ok := keyP.KeyWrapParams.Ec.Parameters[pqcCryptName]
	if !ok {
		return nil, errors.New("provider must be formatted as provider:pqccrypt:pqc://pq?pub=$PQPUB")
	}

	if len(keyP.KeyWrapParams.Ec.Parameters[pqcCryptName]) == 0 {
		return nil, errors.New("provider must be formatted as provider:pqccrypt:pqc://pq?pub=$PQPUB")
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

	wrapper := pqcwrap.NewWrapper()
	_, err = wrapper.SetConfig(ctx, pqcwrap.WithPublicKey(string(pubPEMData)))
	if err != nil {
		return nil, fmt.Errorf("Error creating wrapper %v", err)
	}

	blobInfo, err := wrapper.Encrypt(ctx, keyP.KeyWrapParams.OptsData)
	if err != nil {
		return nil, fmt.Errorf("Error encrypting %v\n", err)
	}

	b, err := protojson.Marshal(blobInfo)
	if err != nil {
		return nil, fmt.Errorf("Error marshalling bytes %v\n", err)
	}

	jsonString, err := json.Marshal(annotationPacket{
		KeyUrl:     pqcURI,
		WrappedKey: b,
		WrapType:   "AES",
	})
	if err != nil {
		return nil, err
	}

	protocolOuputSerialized, err := json.Marshal(keyprovider.KeyProviderKeyWrapProtocolOutput{
		KeyWrapResults: keyprovider.KeyWrapResults{Annotation: jsonString},
	})
	if err != nil {
		return nil, fmt.Errorf("Error marshalling KeyProviderKeyWrapProtocolOutput %v\n", err)
	}

	return &keyproviderpb.KeyProviderKeyWrapProtocolOutput{
		KeyProviderKeyWrapProtocolOutput: protocolOuputSerialized,
	}, nil

}

func (*server) UnWrapKey(ctx context.Context, request *keyproviderpb.KeyProviderKeyWrapProtocolInput) (*keyproviderpb.KeyProviderKeyWrapProtocolOutput, error) {
	log.Println("got UnWrapKey")
	var keyP keyprovider.KeyProviderKeyWrapProtocolInput
	err := json.Unmarshal(request.KeyProviderKeyWrapProtocolInput, &keyP)
	if err != nil {
		return nil, err
	}
	apkt := annotationPacket{}
	err = json.Unmarshal(keyP.KeyUnwrapParams.Annotation, &apkt)
	if err != nil {
		return nil, err
	}

	if *pqcKeyURI != "" {
		if len(keyP.KeyUnwrapParams.Dc.Parameters) == 0 {
			keyP.KeyUnwrapParams.Dc.Parameters = make(map[string][][]byte)
		}
		keyP.KeyUnwrapParams.Dc.Parameters[pqcCryptName] = [][]byte{[]byte(*pqcKeyURI)}
	}

	ciphertext := apkt.WrappedKey
	pqcURI := apkt.KeyUrl

	_, ok := keyP.KeyUnwrapParams.Dc.Parameters[pqcCryptName]
	if ok {
		pqcURI = string(keyP.KeyUnwrapParams.Dc.Parameters[pqcCryptName][0])
	}

	if pqcURI == "" {
		return nil, errors.New("pqcURI cannot be nil")
	}

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

	protocolOuputSerialized, err := json.Marshal(keyprovider.KeyProviderKeyWrapProtocolOutput{
		KeyUnwrapResults: keyprovider.KeyUnwrapResults{OptsData: blobInfo},
	})
	if err != nil {
		return nil, fmt.Errorf("Error marshalling KeyProviderKeyWrapProtocolOutput %v\n", err)
	}

	return &keyproviderpb.KeyProviderKeyWrapProtocolOutput{
		KeyProviderKeyWrapProtocolOutput: protocolOuputSerialized,
	}, nil
}

func main() {

	flag.Parse()

	ctx := context.Background()
	var err error

	wrapper = pqcwrap.NewWrapper()

	if *pqcKeyURI != "" {

		u, err := url.Parse(string(*pqcKeyURI))
		if err != nil {
			log.Fatalf("error parsing prviate URL must be  pqc:// %s", *pqcURI)
		}
		if u.Scheme != "pqc" {
			log.Fatalf("error scheme must be pqc, got %s", u.Scheme)
		}

		m, err := url.ParseQuery(u.RawQuery)
		if err != nil {
			log.Fatalf("error parsing Provider URL: %v", err)
		}

		if m["key"] == nil {
			log.Fatal("error ?key= value must be set")
		}

		privURI := m["key"][0]

		mk, err := url.Parse(privURI)
		if err != nil {
			log.Fatalf("error parsing Provider URL: %v", err)
		}

		switch mk.Scheme {
		case "file":
			b, err := os.ReadFile(mk.Path)
			if err != nil {
				log.Fatalf("Error reading private key file  %v", err)
			}
			_, err = wrapper.SetConfig(ctx, pqcwrap.WithPrivateKey(string(b)))
			if err != nil {
				log.Fatalf("Error creating file wrapper %v", err)
			}

		case "gcpkms":
			ctx := context.Background()

			if *adc != "" {
				os.Setenv("GOOGLE_APPLICATION_CREDENTIALS", *adc)
				//kmsClient, err = kms.NewKeyManagementClient(ctx, option.WithCredentialsFile(*adc))
			}

			_, err = wrapper.SetConfig(ctx, pqcwrap.WithPrivateKey(privURI), pqcwrap.WithKMSKey(true))
			if err != nil {
				log.Fatalf("Error creating KMS wrapper %v", err)
			}

		default:
			log.Fatalf("scheme must be file:// or gcpkms://, got %s", mk.Scheme)
		}
	}

	lis, err := net.Listen("tcp", *grpcport)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	sopts := []grpc.ServerOption{grpc.MaxConcurrentStreams(10)}
	sopts = append(sopts)

	s := grpc.NewServer(sopts...)
	keyproviderpb.RegisterKeyProviderServiceServer(s, &server{})

	log.Printf("Starting gRPC Server at %s", *grpcport)
	s.Serve(lis)

}
