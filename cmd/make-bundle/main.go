package main

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/koshatul/ssl-make-bundle/common/swim"
	"github.com/na4ma4/config"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// nolint: gochecknoglobals // cobra uses globals in main
var rootCmd = &cobra.Command{
	Use:   "make-bundle <cert>",
	Short: "make a bundle from a certificate",
	Args:  cobra.MinimumNArgs(1),
	Run:   mainCommand,
}

// nolint:gochecknoinits // init is used in main for cobra
func init() {
	cobra.OnInitialize(configDefaults)

	rootCmd.PersistentFlags().BoolP("debug", "d", false, "Debug output")
	_ = viper.BindPFlag("debug", rootCmd.PersistentFlags().Lookup("debug"))
	_ = viper.BindEnv("debug", "DEBUG")
}

func main() {
	_ = rootCmd.Execute()
}

func mainCommand(cmd *cobra.Command, args []string) {
	vcfg := config.NewViperConfigFromViper(viper.GetViper(), "make-bundle")

	caPool := swim.NewCertPool()
	// if err != nil {
	// 	log.Fatalf("unable to load system CA Pool: %s", err)
	// }

	f, err := ioutil.ReadFile(args[0])
	if err != nil {
		log.Fatalf("unable to open file(%s): %s", args[0], err)
	}

	block, _ := pem.Decode(f)
	if block == nil {
		log.Fatalf("unable to read certificate file(%s)", args[0])
	}
	if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
		log.Fatalf("supplied file(%s) is not a PEM encoded certificate", args[0])
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatalf("unable to parse certificate from file(%s): %s", args[0], err)
	}

	filepath.Walk(vcfg.GetString("ca.path"), func(path string, info os.FileInfo, err error) error {
		// log.Printf("File: %s", path)

		if strings.HasSuffix(path, ".pem") {
			f, err := ioutil.ReadFile(path)
			if err != nil {
				return nil
			}
			_ = caPool.AppendCertsFromPEM(f)
		}

		return nil
	})

	buf := bytes.NewBuffer(nil)

	pem.Encode(buf, block)

	var walkFunc func(c *x509.Certificate) error

	walkFunc = func(c *x509.Certificate) error {
		if strings.Compare(cert.Issuer.String(), c.Subject.String()) == 0 {
			// log.Printf("Subject: %s", cert.Subject.String())
			// log.Printf("Issuer: %s", cert.Issuer.String())

			pem.Encode(buf, &pem.Block{
				Type:  "CERTIFICATE",
				Bytes: c.Raw,
			})

			if strings.Compare(c.Subject.String(), c.Issuer.String()) == 0 {
				// log.Printf("[root]Subject: %s", cert.Subject.String())
				// log.Printf("[root]Issuer: %s", cert.Issuer.String())
				return errors.New("Found the root CA")
			}

			cert = c

			caPool.Walk(walkFunc)

			return errors.New("finished loop")
		}

		return nil
	}

	caPool.Walk(walkFunc)

	out := bytes.NewReader(buf.Bytes())

	io.Copy(os.Stdout, out)
}
