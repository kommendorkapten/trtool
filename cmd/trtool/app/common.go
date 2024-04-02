package app

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/kommendorkapten/trtool/pkg/slice"

	pc "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	ptr "github.com/sigstore/protobuf-specs/gen/pb-go/trustroot/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

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

	if endStr != "" {
		if end, err := time.Parse(time.RFC3339, endStr); err == nil {
			ca.ValidFor.End = timestamppb.New(end)
		} else {
			return nil, fmt.Errorf("invalid end date %s: %w",
				endStr, err)
		}
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
		return nil, fmt.Errorf("failed to load pem file: %w", err)

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
	var local = make([]*x509.Certificate, len(certs))
	var prev *x509.Certificate

	copy(local, certs)
	for len(local) > 0 {
		var done bool

		for i := range local {
			cand := local[i]
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
				local = slice.DeleteElement(local, i)
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
