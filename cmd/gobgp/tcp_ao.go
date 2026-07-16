// Copyright (C) 2026 The GoBGP Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	"github.com/osrg/gobgp/v4/api"
	"github.com/spf13/cobra"
)

func parseTcpAoAlgorithm(value string) (api.TcpAoAlgorithm, error) {
	switch strings.ToLower(value) {
	case "hmac-sha-1-96", "hmac-sha1-96", "hmac_sha_1_96":
		return api.TcpAoAlgorithm_TCP_AO_ALGORITHM_HMAC_SHA1_96, nil
	case "aes-128-cmac-96", "aes_128_cmac_96":
		return api.TcpAoAlgorithm_TCP_AO_ALGORITHM_AES_128_CMAC_96, nil
	case "hmac-sha-256-96", "hmac-sha256-96", "hmac_sha_256_96":
		return api.TcpAoAlgorithm_TCP_AO_ALGORITHM_HMAC_SHA256_96, nil
	case "hmac-sha-256-128", "hmac-sha256-128", "hmac_sha_256_128":
		return api.TcpAoAlgorithm_TCP_AO_ALGORITHM_HMAC_SHA256_128, nil
	default:
		return api.TcpAoAlgorithm_TCP_AO_ALGORITHM_UNSPECIFIED, fmt.Errorf("unsupported TCP-AO algorithm %q", value)
	}
}

func formatTcpAoAlgorithm(algorithm api.TcpAoAlgorithm) string {
	switch algorithm {
	case api.TcpAoAlgorithm_TCP_AO_ALGORITHM_HMAC_SHA1_96:
		return "hmac-sha-1-96"
	case api.TcpAoAlgorithm_TCP_AO_ALGORITHM_AES_128_CMAC_96:
		return "aes-128-cmac-96"
	case api.TcpAoAlgorithm_TCP_AO_ALGORITHM_HMAC_SHA256_96:
		return "hmac-sha-256-96"
	case api.TcpAoAlgorithm_TCP_AO_ALGORITHM_HMAC_SHA256_128:
		return "hmac-sha-256-128"
	default:
		return "unspecified"
	}
}

func parseTcpAoID(value string) (uint32, error) {
	id, err := strconv.ParseUint(value, 10, 8)
	if err != nil {
		return 0, fmt.Errorf("TCP-AO key ID %q must be an integer in 0..255: %w", value, err)
	}
	return uint32(id), nil
}

func parseTcpAoKey(value string) (*api.TcpAoKey, error) {
	fields := strings.Split(value, ",")
	if len(fields) != 4 && len(fields) != 5 {
		return nil, fmt.Errorf("TCP-AO key must be send-id,receive-id,algorithm,base64-master-key[,exclude-tcp-options]")
	}
	sendID, err := parseTcpAoID(fields[0])
	if err != nil {
		return nil, err
	}
	receiveID, err := parseTcpAoID(fields[1])
	if err != nil {
		return nil, err
	}
	algorithm, err := parseTcpAoAlgorithm(fields[2])
	if err != nil {
		return nil, err
	}
	masterKey, err := base64.StdEncoding.DecodeString(fields[3])
	if err != nil {
		return nil, fmt.Errorf("TCP-AO master key must be base64 encoded: %w", err)
	}
	excludeTCPOptions := false
	if len(fields) == 5 {
		if fields[4] != "exclude-tcp-options" {
			return nil, fmt.Errorf("unknown TCP-AO key option %q", fields[4])
		}
		excludeTCPOptions = true
	}
	return &api.TcpAoKey{
		SendId:            sendID,
		ReceiveId:         receiveID,
		Algorithm:         algorithm,
		ExcludeTcpOptions: excludeTCPOptions,
		MasterKey:         masterKey,
	}, nil
}

func parseTcpAoDeleteKey(value string) (*api.TcpAoKey, error) {
	fields := strings.Split(value, ",")
	if len(fields) != 2 {
		return nil, fmt.Errorf("TCP-AO delete key must be send-id,receive-id")
	}
	sendID, err := parseTcpAoID(fields[0])
	if err != nil {
		return nil, err
	}
	receiveID, err := parseTcpAoID(fields[1])
	if err != nil {
		return nil, err
	}
	return &api.TcpAoKey{SendId: sendID, ReceiveId: receiveID}, nil
}

func parseTcpAoKeys(values []string, parse func(string) (*api.TcpAoKey, error)) ([]*api.TcpAoKey, error) {
	keys := make([]*api.TcpAoKey, 0, len(values))
	for _, value := range values {
		key, err := parse(value)
		if err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	return keys, nil
}

func getTcpAoKeychains(name string) ([]*api.TcpAoKeychain, error) {
	stream, err := client.ListTcpAoKeychain(ctx, &api.ListTcpAoKeychainRequest{Name: name})
	if err != nil {
		return nil, err
	}
	chains := make([]*api.TcpAoKeychain, 0)
	for {
		response, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		chains = append(chains, response.Keychain)
	}
	sort.Slice(chains, func(i, j int) bool { return chains[i].Name < chains[j].Name })
	return chains, nil
}

func showTcpAoKeychains(name string) error {
	chains, err := getTcpAoKeychains(name)
	if err != nil {
		return err
	}
	if globalOpts.Json {
		value, err := json.Marshal(chains)
		if err != nil {
			return err
		}
		fmt.Println(string(value))
		return nil
	}
	if globalOpts.Quiet {
		for _, chain := range chains {
			fmt.Println(chain.Name)
		}
		return nil
	}
	fmt.Printf("%-20s %7s %10s %-18s %s\n", "Name", "Send ID", "Receive ID", "Algorithm", "Exclude TCP options")
	for _, chain := range chains {
		for _, key := range chain.Keys {
			fmt.Printf("%-20s %7d %10d %-18s %t\n", chain.Name, key.SendId, key.ReceiveId, formatTcpAoAlgorithm(key.Algorithm), key.ExcludeTcpOptions)
		}
	}
	return nil
}

func newKeychainCmd() *cobra.Command {
	var addKeys []string
	var updateAddKeys []string
	var updateDeleteKeys []string

	keychainCmd := &cobra.Command{
		Use:  "keychain [name]",
		Args: cobra.MaximumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			name := ""
			if len(args) == 1 {
				name = args[0]
			}
			return showTcpAoKeychains(name)
		},
	}
	addCmd := &cobra.Command{
		Use:  "add <name>",
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if len(addKeys) == 0 {
				return fmt.Errorf("at least one --key is required")
			}
			keys, err := parseTcpAoKeys(addKeys, parseTcpAoKey)
			if err != nil {
				return err
			}
			_, err = client.AddTcpAoKeychain(ctx, &api.AddTcpAoKeychainRequest{Keychain: &api.TcpAoKeychain{Name: args[0], Keys: keys}})
			return err
		},
	}
	addCmd.Flags().StringArrayVar(&addKeys, "key", nil, "send-id,receive-id,algorithm,base64-master-key[,exclude-tcp-options] (repeatable)")

	updateCmd := &cobra.Command{
		Use:  "update <name>",
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if len(updateAddKeys) == 0 && len(updateDeleteKeys) == 0 {
				return fmt.Errorf("at least one --add-key or --delete-key is required")
			}
			add, err := parseTcpAoKeys(updateAddKeys, parseTcpAoKey)
			if err != nil {
				return err
			}
			deleteKeys, err := parseTcpAoKeys(updateDeleteKeys, parseTcpAoDeleteKey)
			if err != nil {
				return err
			}
			_, err = client.UpdateTcpAoKeychain(ctx, &api.UpdateTcpAoKeychainRequest{Name: args[0], AddKeys: add, DeleteKeys: deleteKeys})
			return err
		},
	}
	updateCmd.Flags().StringArrayVar(&updateAddKeys, "add-key", nil, "send-id,receive-id,algorithm,base64-master-key[,exclude-tcp-options] (repeatable)")
	updateCmd.Flags().StringArrayVar(&updateDeleteKeys, "delete-key", nil, "send-id,receive-id (repeatable)")

	deleteCmd := &cobra.Command{
		Use:  "del <name>",
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			_, err := client.DeleteTcpAoKeychain(ctx, &api.DeleteTcpAoKeychainRequest{Name: args[0]})
			return err
		},
	}

	keychainCmd.AddCommand(addCmd, updateCmd, deleteCmd)
	return keychainCmd
}
