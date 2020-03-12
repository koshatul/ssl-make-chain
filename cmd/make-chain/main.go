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

	"github.com/koshatul/ssl-make-chain/common/swim"
	"github.com/na4ma4/config"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// nolint: gochecknoglobals,gomnd // cobra uses globals in main
var rootCmd = &cobra.Command{
	Use:   "make-chain <cert>",
	Short: "make a chain from a single certificate",
	Args:  cobra.MinimumNArgs(1),
	Run:   mainCommand,
}

// nolint:gochecknoinits // init is used in main for cobra
func init() {
	rootCmd.PersistentFlags().BoolP("debug", "d", false, "Debug output")
	_ = viper.BindPFlag("debug", rootCmd.PersistentFlags().Lookup("debug"))
	_ = viper.BindEnv("debug", "DEBUG")

	rootCmd.PersistentFlags().StringP("ca-path", "c", ".", "Path to certificate store")
	_ = viper.BindPFlag("ca-path", rootCmd.PersistentFlags().Lookup("ca-path"))
	_ = viper.BindEnv("ca-path", "CA_PATH")
}

func main() {
	_ = rootCmd.Execute()
}

func readFileIntoPool(cfg config.Conf, path string, pool *swim.CertPool) error {
	if cfg.GetBool("debug") {
		log.Printf("Reading Certificate File: %s", path)
	}

	f, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}

	_ = pool.AppendCertsFromPEM(f)

	return nil
}

func printDebugf(cfg config.Conf, format string, v ...interface{}) {
	if cfg.GetBool("debug") {
		log.Printf(format, v...)
	}
}

func readCertificate(path string) (*x509.Certificate, *pem.Block, error) {
	f, err := ioutil.ReadFile(path)
	if err != nil {
		log.Fatalf("unable to open file(%s): %s", path, err)
	}

	block, _ := pem.Decode(f)
	if block == nil {
		log.Fatalf("unable to read certificate file(%s)", path)
	} else if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
		log.Fatalf("supplied file(%s) is not a PEM encoded certificate", path)
	}

	cert, err := x509.ParseCertificate(block.Bytes)

	return cert, block, err
}

func mainCommand(cmd *cobra.Command, args []string) {
	vcfg := config.NewViperConfig("make-chain", "${HOME}/.config/make-chain.toml")
	vcfg.SetBool("debug", viper.GetBool("debug"))
	vcfg.SetString("ca-path", viper.GetString("ca-path"))

	caPool := swim.NewCertPool()

	cert, block, err := readCertificate(args[0])
	if err != nil {
		log.Fatalf("unable to parse certificate from file(%s): %s", args[0], err)
	}

	if _, err := os.Stat("/etc/ssl/cert.pem"); err == nil {
		printDebugf(vcfg, "loading system ca-certificates /etc/ssl/cert.pem")

		_ = readFileIntoPool(vcfg, "/etc/ssl/cert.pem", caPool)
	}

	_ = filepath.Walk(os.ExpandEnv(vcfg.GetString("ca-path")), func(path string, info os.FileInfo, err error) error {
		if strings.HasSuffix(path, ".pem") || strings.HasSuffix(path, ".crt") {
			return readFileIntoPool(vcfg, path, caPool)
		}

		return nil
	})

	buf := bytes.NewBuffer(nil)
	_ = pem.Encode(buf, block)

	var walkFunc func(c *x509.Certificate) error
	walkFunc = func(c *x509.Certificate) error {
		printDebugf(vcfg, "testing chain cert: %s", c.Subject.String())

		if strings.Compare(cert.Issuer.String(), c.Subject.String()) == 0 {
			printDebugf(vcfg, "found chain cert: %s", c.Subject.String())

			_ = pem.Encode(buf, &pem.Block{
				Type:  "CERTIFICATE",
				Bytes: c.Raw,
			})

			if strings.Compare(c.Subject.String(), c.Issuer.String()) == 0 {
				printDebugf(vcfg, "found the root CA: %s", c.Subject.String())

				return errors.New("found the root CA")
			}

			cert = c
			_ = caPool.Walk(walkFunc)

			return errors.New("finished loop")
		}

		return nil
	}

	_ = caPool.Walk(walkFunc)
	out := bytes.NewReader(buf.Bytes())
	_, _ = io.Copy(os.Stdout, out)
}
