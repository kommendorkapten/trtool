package app

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/peterbourgon/ff/v3/ffcli"
	ptr "github.com/sigstore/protobuf-specs/gen/pb-go/trustroot/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	TypeCA   = "ca"
	TypeTSA  = "tsa"
	TypeTLog = "tlog"
)

func Add() *ffcli.Command {
	var (
		flagset = flag.NewFlagSet("trtool add", flag.ExitOnError)
		tr      = flagset.String("f", "trusted_root.json", "Trusted root file to update")
		nType   = flagset.String("type", "", "the type, ca, tsa or tlog")
		uri     = flagset.String("uri", "", "tye uri for the new entity")
		pemFile = flagset.String("pem", "", "Verifictation material to add")
		start   = flagset.String("start", "", "Validity start time")
		end     = flagset.String("end", "", "Validity end time")
		prevEnd = flagset.String("prev-end", "", "End time for currently valid chain")
		verbose = flagset.Bool("verbose", false, "verbose mode")
	)

	return &ffcli.Command{
		Name:       "add",
		ShortUsage: "trtool add -uri foo.bar -ca file.pem",
		ShortHelp:  "Add a certificate chain to a CA",
		LongHelp:   "Add a certificate chain to a CA. If no start time is set, current time is used. If no Previous end is set, the next chain's start time is used",
		FlagSet:    flagset,
		Exec: func(ctx context.Context, args []string) error {
			if !(*nType == TypeCA || *nType == TypeTSA || *nType == TypeTLog) {
				return flag.ErrHelp
			}
			if *uri == "" {
				return flag.ErrHelp
			}
			if *pemFile == "" {
				return flag.ErrHelp
			}
			if *tr == "" {
				return flag.ErrHelp
			}

			return AddCmd(*tr, *nType, *uri, *pemFile, *start, *end, *prevEnd, *verbose)
		},
	}
}

func AddCmd(trp, nType, uri, pemFile, start, end, prevEnd string, verbose bool) error {
	var tr ptr.TrustedRoot
	var buf []byte
	var prevEndTs time.Time
	var err error

	if prevEnd != "" {
		if prevEndTs, err = time.Parse(time.RFC3339, prevEnd); err != nil {
			return fmt.Errorf("invalid prev-end %s %w", start, err)
		}
	}

	if buf, err = os.ReadFile(trp); err != nil {
		return fmt.Errorf("Could not read trusted root %s: %w",
			trp, err)
	}

	if err = protojson.Unmarshal(buf, &tr); err != nil {
		return fmt.Errorf("failed to unmarhsal trusted root: %w", err)
	}

	switch nType {
	case TypeCA:
		fallthrough
	case TypeTSA:
		err = addCA(&tr, nType, uri, pemFile, start, end, prevEndTs, verbose)
	case TypeTLog:
		err = fmt.Errorf("adding transparency logs is not yet supported")
	default:
		return flag.ErrHelp
	}

	if err != nil {
		return err
	}
	// Marshal to JSON and print to stdout

	if buf, err = protojson.Marshal(&tr); err != nil {
		return err
	}

	fmt.Println(string(buf))

	return nil
}

func addCA(tr *ptr.TrustedRoot, caType, uri, pemFile, start, end string,
	prevEndTs time.Time, verbose bool) error {
	var newCA *ptr.CertificateAuthority
	var ca *[]*ptr.CertificateAuthority
	var err error

	if newCA, err = newCertificateAuthority(pemFile, start, end, uri, verbose); err != nil {
		return err
	}

	// Close previous entry if timestamp is open
	if caType == TypeCA {
		ca = &tr.CertificateAuthorities
	} else {
		ca = &tr.TimestampAuthorities
	}
	var last = len(*ca) - 1
	if last >= 0 {
		if (*ca)[last].ValidFor.End == nil {
			if prevEndTs.IsZero() {
				(*ca)[last].ValidFor.End = newCA.ValidFor.Start
			} else {
				(*ca)[last].ValidFor.End = timestamppb.New(prevEndTs)
			}
		}
	}

	// Add new entry
	if caType == TypeCA {
		tr.CertificateAuthorities = append(*ca, newCA)
	} else {
		tr.TimestampAuthorities = append(*ca, newCA)
	}

	return nil
}
