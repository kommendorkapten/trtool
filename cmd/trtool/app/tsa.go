package app

import (
	"context"
	"flag"

	"github.com/peterbourgon/ff/v3/ffcli"
)

func Tsa() *ffcli.Command {
	var (
		flagset = flag.NewFlagSet("trtool tsa", flag.ExitOnError)
		pemFile = flagset.String("a", "", "Certificate chain to add")
	)

	return &ffcli.Command{
		Name:       "tsa",
		ShortUsage: "trtool tsa -a pem-file -d Subject",
		ShortHelp:  "Add or delete TSA",
		LongHelp:   "Add or delete TSA",
		FlagSet:    flagset,
		Exec: func(ctx context.Context, args []string) error {
			if *pemFile == "" {
				return flag.ErrHelp
			}

			return nil
		},
	}
}
