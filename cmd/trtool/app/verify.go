package app

import (
	"context"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/peterbourgon/ff/v3/ffcli"
	"github.com/sigstore/protobuf-specs/gen/pb-go/trustroot/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

func Verify() *ffcli.Command {
	var (
		flagset = flag.NewFlagSet("trtool verify", flag.ExitOnError)
		root    = flagset.String("f", "", "Trusted root to verify")
		verbose = flagset.Bool("v", false, "verbose mode")
	)

	return &ffcli.Command{
		Name:       "verify",
		ShortUsage: "trtool verify -f file.json",
		ShortHelp:  "Verify trusted root",
		LongHelp:   "Verify trusted root",
		FlagSet:    flagset,
		Exec: func(ctx context.Context, args []string) error {
			if *root == "" {
				return flag.ErrHelp
			}

			b, err := os.ReadFile(*root)
			if err != nil {
				return err
			}

			return VerifyCmd(b, *verbose)
		},
	}
}

func VerifyCmd(b []byte, verbose bool) error {
	var trustRoot v1.TrustedRoot
	var err error
	var valid = true

	if err = protojson.Unmarshal(b, &trustRoot); err != nil {
		return err
	}

	for _, ca := range trustRoot.CertificateAuthorities {
		if this := VerifyCertChain(ca, verbose); !this {
			valid = false
		}
	}

	for _, ca := range trustRoot.TimestampAuthorities {
		if this := VerifyCertChain(ca, verbose); !this {
			valid = false
		}
	}

	if !valid {
		return errors.New("verification failed")
	}

	return nil
}

func VerifyCertChain(ca *v1.CertificateAuthority, verbose bool) bool {
	var parsed []*x509.Certificate
	var valid = true

	if verbose {
		fmt.Printf("Verifying OU='%s' CN='%s' of length %d\n",
			ca.Subject.Organization,
			ca.Subject.CommonName,
			len(ca.CertChain.Certificates),
		)
	}

	var child *x509.Certificate
	for i, cert := range ca.CertChain.Certificates {
		c, err := x509.ParseCertificate(cert.RawBytes)
		if err != nil {
			panic(err)
		}

		if verbose {
			fmt.Printf("  Loaded OU='%s' CN='%s' CA:%v MaxPathLen %d at pos %d\n",
				c.Subject.Organization[0],
				c.Subject.CommonName,
				c.IsCA,
				c.MaxPathLen,
				i,
			)
			fmt.Printf("    issuer OU='%s' CN='%s'\n",
				c.Issuer.Organization[0],
				c.Issuer.CommonName,
			)
		}

		if child != nil {
			// Verify the chain.
			// The order is leaf, intermediate(*), root
			// So when verifying a cert, make sure that the previous
			// certificate was signed by the current one.
			if child.Issuer.Organization[0] != c.Subject.Organization[0] {
				fmt.Printf("Found issuer organization '%s', expected '%s'\n",
					child.Issuer.Organization[0],
					c.Subject.Organization,
				)
				valid = false
			}
			if child.Issuer.CommonName != c.Subject.CommonName {
				fmt.Printf("Found issuer common name '%s', expected '%s'\n",
					child.Issuer.CommonName,
					c.Subject.CommonName,
				)
				valid = false
			}
			if len(child.AuthorityKeyId) != len(c.SubjectKeyId) {
				fmt.Printf("Unexpected authority key id")
				valid = false
			}
			for i := range child.AuthorityKeyId {
				if child.AuthorityKeyId[i] != c.SubjectKeyId[i] {
					fmt.Printf("Unexpected authority key id")
					valid = false
					break
				}
			}
		}
		child = c

		parsed = append(parsed, c)
	}

	// The last certificate is the root, verify that the subject matches
	root := parsed[len(parsed)-1]
	if !root.IsCA {
		fmt.Println("expected root certificate last")
		valid = false
	}

	if root.Subject.Organization[0] != ca.Subject.Organization {
		fmt.Printf("Found organization '%s', expected '%s'\n",
			root.Subject.Organization[0],
			ca.Subject.Organization,
		)
		valid = false
	}
	if root.Subject.CommonName != ca.Subject.CommonName {
		fmt.Printf("Found common name '%s', expected '%s'\n",
			root.Subject.CommonName,
			ca.Subject.CommonName,
		)
		valid = false
	}
	if verbose {
		fmt.Printf("------------------------------------------------------------------------\n")
	}

	return valid
}
