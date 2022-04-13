package main

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"github.com/caarlos0/env/v6"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"io/ioutil"
	"software.sslmate.com/src/go-pkcs12" 
	"os"
	"time"
)

type config struct {
	Mode            bool   `env:"FILE_MODE" envDefault:false`
	Key             string `env:"KEY"`
	Certificate     string `env:"CERTIFICATE"`
	KeyFile         string `env:"KEY_FILE,file"`
	CertificateFile string `env:"CERTIFICATE_FILE,file"`
	OutputP12       string `env:"OUTPUT_FILE" envDefault:"/var/run/secrets/truststore.p12"`
}

func main() {
	zerolog.DurationFieldUnit = time.Second
	if err := run(); err != nil {
		log.Fatal().Err(err).Msg("Failed to run")
	}
	log.Info().Msg("Gracefully exiting")
}

func run() error {
	cfg := config{}

	if err := env.Parse(&cfg); err != nil {
		return err
	}

	var key, certificate string

	if cfg.Mode == true {
		key = cfg.KeyFile
		certificate = cfg.CertificateFile
	} else {
		key = cfg.Key
		certificate = cfg.Certificate
	}

	pemPrivateKey, err := readPem("PRIVATE KEY", key)
	if err != nil {
		return err
	}

	pemCertificate, err := readPem("CERTIFICATE", certificate)
	if err != nil {
		return err
	}

 cert, err := x509.ParseCertificate(pemCertificate)

    if err != nil {
        panic(err)
    }

	pfxBytes, err := pkcs12.Encode(rand.Reader, pemPrivateKey, cert, []*x509.Certificate{}, pkcs12.DefaultPassword)

    if err != nil {
        panic(err)
    }

    // validate output
    _, _, _, err = pkcs12.DecodeChain(pfxBytes, pkcs12.DefaultPassword)
    if err != nil {
        panic(err)
    }

	// write output
    if err := ioutil.WriteFile(
        cfg.OutputP12,
        pfxBytes,
        os.ModePerm,
    ); err != nil {
        panic(err)
    }

	return nil
}

func readPem(expectedType string, data string) ([]byte, error) {
	b, _ := pem.Decode([]byte(data))
	if b == nil {
		return nil, errors.New("should have at least one pem block")
	}

	if b.Type != expectedType {
		return nil, errors.New("should be a " + expectedType)
	}

	return b.Bytes, nil
}
