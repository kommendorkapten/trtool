package app

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/kommendorkapten/trtool/pkg/slice"

	"github.com/peterbourgon/ff/v3/ffcli"
	pc "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	ptr "github.com/sigstore/protobuf-specs/gen/pb-go/trustroot/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func InitRoot() *ffcli.Command {
	var (
		flagset  = flag.NewFlagSet("trtool init", flag.ExitOnError)
		ca       = flagset.String("ca", "", "Certificate bundle to add for the CA")
		tsa      = flagset.String("tsa", "", "Certificate bundle to add for the TSA")
		caStart  = flagset.String("ca-start", "", "Validity start date for the CA")
		caEnd    = flagset.String("ca-end", "", "Validity end date for the CA")
		tsaStart = flagset.String("tsa-start", "", "Validity start date for the TSA")
		tsaEnd   = flagset.String("tsa-end", "", "Validity end date for the TSA")
		caURI    = flagset.String("ca-uri", "", "URI for the CA")
		tsaURI   = flagset.String("tsa-uri", "", "URI for the TSA")
		verbose  = flagset.Bool("v", false, "verbose mode")
	)

	return &ffcli.Command{
		Name:       "init",
		ShortUsage: "trtool init ",
		ShortHelp:  "Initialize a trusted root",
		LongHelp:   "Initialize a trusted root",
		FlagSet:    flagset,
		Exec: func(ctx context.Context, args []string) error {
			if *ca != "" && *caStart == "" {
				return flag.ErrHelp
			}
			if *tsa != "" && *tsaStart == "" {
				return flag.ErrHelp
			}

			return InitRootCmd(*ca, *caStart, *caEnd, *caURI,
				*tsa, *tsaStart, *tsaEnd, *tsaURI,
				*verbose)
		},
	}
}

func InitRootCmd(ca, caStart, caEnd, caURI,
	tsa, tsaStart, tsaEnd, tsaURI string, verbose bool) error {
	var tr = ptr.TrustedRoot{
		MediaType: "application/vnd.dev.sigstore.trustedroot+json;version=0.1",
	}
	var b []byte
	var err error

	if ca != "" {
		protoCA, err := newCertificateAuthority(ca, caStart,
			caEnd, caURI, verbose)
		if err != nil {
			return err
		}
		tr.CertificateAuthorities = []*ptr.CertificateAuthority{
			protoCA,
		}
	}

	if tsa != "" {
		protoCA, err := newCertificateAuthority(tsa, tsaStart,
			tsaEnd, tsaURI, verbose)
		if err != nil {
			return err
		}
		tr.TimestampAuthorities = []*ptr.CertificateAuthority{
			protoCA,
		}
	}

	if b, err = protojson.Marshal(&tr); err != nil {
		return err
	}

	fmt.Println(string(b))

	return nil
}

func newCertificateAuthority(pem, startStr, endStr, url string, verbose bool) (*ptr.CertificateAuthority, error) {
	start, err := time.Parse(time.RFC3339, startStr)
	if err != nil {
		return nil, err
	}
	chain, err := loadChain(pem, verbose)
	if err != nil {
		return nil, err
	}
	protoChain := make([]*pc.X509Certificate, len(chain))
	root := chain[len(chain)-1]

	if start.Before(root.NotBefore) {
		return nil, fmt.Errorf("invalid validity time, provided %s is before root certificate's 'not before' %s",
			start, root.NotBefore)
	}
	if start.After(root.NotAfter) {
		return nil, fmt.Errorf("invalid validity time, provided %s is after root certificate's 'not after' %s",
			start, root.NotAfter)
	}

	for i, c := range chain {
		protoChain[i] = &pc.X509Certificate{
			RawBytes: c.Raw,
		}
	}
	var org string
	if len(root.Subject.Organization) > 0 {
		org = root.Subject.Organization[0]
	}
	ca := ptr.CertificateAuthority{
		Subject: &pc.DistinguishedName{
			Organization: org,
			CommonName:   root.Subject.CommonName,
		},
		Uri: url,
		CertChain: &pc.X509CertificateChain{
			Certificates: protoChain,
		},
		ValidFor: &pc.TimeRange{
			Start: timestamppb.New(start),
		},
	}

	if end, err := time.Parse(time.RFC3339, endStr); err == nil {
		ca.ValidFor.End = timestamppb.New(end)
	}

	return &ca, nil
}

func loadChain(p string, verbose bool) ([]*x509.Certificate, error) {
	var b []byte
	var err error
	var certs []*x509.Certificate
	var rest []byte
	var block *pem.Block

	if b, err = os.ReadFile(p); err != nil {
		panic(err)
	}

	for {
		block, rest = pem.Decode(b)
		if len(block.Bytes) == 0 {
			break
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			fmt.Println("Invalid certificate found")
			panic(err)
		}
		certs = append(certs, c)

		if verbose {
			fmt.Println("Adding certificate", c.Subject.CommonName)
		}

		// There may be some new lines at the end of the file,
		// and those will be passed to Decode which panics.
		if len(rest) < 10 {
			break
		}

		b = rest
	}

	return orderCertChain(certs)
}

// Order the chain so it's leaf, intermediate(*), root
// This is the most naive algorithm, but N is expected to be SMALL.
// Loop through the certs and find the root (self signed) then
// continue to find the next cert which has the previous cert's
// subject key id as it's authority key id.
// This assumes the chain does not have any branches.
// Once finished, the chain is ordered from root to leaf, so it has
// to be reversed.
func orderCertChain(certs []*x509.Certificate) ([]*x509.Certificate, error) {
	var tmp = make([]*x509.Certificate, 0, len(certs))
	var prev *x509.Certificate

	for len(certs) > 0 {
		var done bool

		for i := range certs {
			cand := certs[i]
			var target string

			if prev == nil {
				// Find the root
				target = cand.Subject.CommonName
			} else {
				// Find the item with previous subject key id
				// as candidate's autority key id
				target = prev.Subject.CommonName
			}

			// Match on relaxed name chaining per RFC5280
			// Only the common name is currently used
			if cand.Issuer.CommonName == target {
				done = true
				tmp = append(tmp, cand)
				certs = slice.DeleteElement(certs, i)
				prev = cand
				break
			}
		}

		if !done {
			// No cert found that follows this chain
			return nil, errors.New("incomplete certificate chain")
		}
	}

	return slice.Reverse(tmp), nil
}
