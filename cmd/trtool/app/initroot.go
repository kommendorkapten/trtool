package app

import (
	"context"
	"flag"
	"fmt"

	"github.com/peterbourgon/ff/v3/ffcli"
	ptr "github.com/sigstore/protobuf-specs/gen/pb-go/trustroot/v1"
	"google.golang.org/protobuf/encoding/protojson"
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
