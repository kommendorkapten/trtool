package app

import (
	"context"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

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

	valid = VerifyCertChains(trustRoot.CertificateAuthorities, verbose)
	valid = VerifyCertChains(trustRoot.TimestampAuthorities, verbose) && valid

	if !valid {
		return errors.New("verification failed")
	} else if verbose {
		fmt.Println("Trusted root is valid")
	}

	return nil
}

func VerifyCertChains(cas []*v1.CertificateAuthority, verbose bool) bool {
	var valid = true
	var prev *v1.CertificateAuthority

	for _, ca := range cas {
		if ok := VerifyCertChain(ca, verbose); !ok {
			valid = false
		}
		// Verify the order. They SHOULD be orderd from oldes to
		// newest (active)
		if prev != nil {
			if ca.ValidFor.Start.AsTime().Before(prev.ValidFor.Start.AsTime()) {
				fmt.Printf("WARING: %s [%s] should be listed after %s [%s]\n",
					ca.Uri,
					ca.ValidFor.Start.AsTime().Format(time.RFC3339),
					prev.Uri,
					prev.ValidFor.Start.AsTime().Format(time.RFC3339),
				)
			}
		}
		prev = ca
	}

	return valid
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

		// Verify that the CA's start time is equal to or later than
		// the certificate's not before.
		if c.NotBefore.After(ca.ValidFor.Start.AsTime()) {
			fmt.Printf("Error verifying certificate: %s\n", c.Subject.CommonName)
			fmt.Printf("Bundle's validity.start %s\n", ca.ValidFor.Start.AsTime())
			fmt.Printf("Certificate's not before %s\n", c.NotBefore)

			fmt.Println("Certificate's 'not before' must be before the CA's validity time as specified in the bundle")
			valid = false
		}
		// Verify that the CA's end time is not after the certificate's
		// not after.
		if ca.ValidFor.End != nil && ca.ValidFor.End.AsTime().After(c.NotAfter) {
			fmt.Println("Certificate's 'not after' is greater than the CA's validity time as specified in the bundle")
			valid = false
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
			// So when verifying a cert, make sure that the
			// previous certificate was signed by the current one.
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
				fmt.Printf("Unexpected authority key id\n")
				valid = false
			}
			for i := range child.AuthorityKeyId {
				if i >= len(c.SubjectKeyId) {
					fmt.Printf("WARNING: missing SubjectKeyId on %s\n",
						c.Subject.CommonName,
					)
					break
				}
				if child.AuthorityKeyId[i] != c.SubjectKeyId[i] {
					fmt.Printf("Unexpected authority key id\n")
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
