package app

import (
	"context"
	"flag"
	"fmt"
	"strings"

	"github.com/peterbourgon/ff/v3/ffcli"
	ptr "github.com/sigstore/protobuf-specs/gen/pb-go/trustroot/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

func SCInit() *ffcli.Command {
	var (
		flagset = flag.NewFlagSet("trtool sc-init", flag.ExitOnError)
		ca      = flagset.String("ca", "", "URL to the ca")
		oidc    = flagset.String("op", "", "URL to the OIDC Provider")
		tlog    = flagset.String("tlog", "", "Comma separated list of transparency log URLs")
		tsa     = flagset.String("tsa", "", "Comma separated list of timetsamp authorities URLs")
	)

	return &ffcli.Command{
		Name:       "sc-init",
		ShortUsage: "trtool sc-init -ca https://test.com -tlog https://example.com,https://test.com",
		ShortHelp:  "Initialize a signing config",
		LongHelp:   "Initialize a signing config",
		FlagSet:    flagset,
		Exec: func(ctx context.Context, args []string) error {
			var tlogs []string
			var tsas []string

			if *tlog != "" {
				tlogs = strings.Split(*tlog, ",")
			}

			if *tsa != "" {
				tsas = strings.Split(*tsa, ",")
			}

			return SCInitCmd(*ca, *oidc, tlogs, tsas)
		},
	}
}

func SCInitCmd(ca, oidc string, tlogs, tsas []string) error {
	const mediaType = "application/vnd.dev.sigstore.signingconfig.v0.1+json"
	var buf []byte
	var sc = ptr.SigningConfig{
		MediaType: mediaType,
		CaUrl: ca,
		OidcUrl: oidc,
		TlogUrls: tlogs,
		TsaUrls: tsas,
	}
	var err error

	if buf, err = protojson.Marshal(&sc); err != nil {
		return err
	}

	fmt.Println(string(buf))

	return nil
}
