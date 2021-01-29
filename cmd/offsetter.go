package cmd

import (
	"strconv"
	"strings"

	"github.com/criticalstack/swoll/pkg/kernel"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func SetOffsetsFromArgs(probe *kernel.Probe, cmd *cobra.Command, args []string) error {
	nodetect, err := cmd.Flags().GetBool("no-detect-offsets")
	if err != nil {
		return err
	}

	if !nodetect {
		if err := probe.DetectAndSetOffsets(); err != nil {
			return err
		}
	} else {
		offset, err := cmd.Flags().GetString("nsproxy-offset")
		if err != nil {
			return err
		}

		if offset != "" {
			offset = strings.TrimPrefix(offset, "0x")
			offset, err := strconv.ParseInt(offset, 16, 64)
			if err != nil {
				return err
			}

			setter, err := kernel.NewOffsetter(probe.Module())
			if err != nil {
				log.Fatal(err)
			}

			log.Infof("Setting task_struct->nsproxy offset to: %x\n", offset)

			if err := setter.Set("nsproxy", kernel.OffsetValue(offset)); err != nil {
				return err
			}
		}

		offset, err = cmd.Flags().GetString("pidns-offset")
		if err != nil {
			return err
		}

		if offset != "" {
			offset = strings.TrimPrefix(offset, "0x")
			offset, err := strconv.ParseInt(offset, 16, 64)
			if err != nil {
				return err
			}

			setter, err := kernel.NewOffsetter(probe.Module())
			if err != nil {
				log.Fatal(err)
			}

			log.Infof("Setting pid_namespace->ns offset to: %x\n", offset)

			if err := setter.Set("pid_ns_common", kernel.OffsetValue(offset)); err != nil {
				return err
			}

		}

	}

	return nil

}
