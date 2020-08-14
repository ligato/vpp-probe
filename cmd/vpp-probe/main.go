//  Copyright (c) 2020 Cisco and/or its affiliates.
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at:
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

package main

import (
	"os"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"go.ligato.io/vpp-probe/version"
)

const Logo = `
 ___    _________________                        ______       
 __ |  / /__  __ \__  __ \   _______________________  /______ 
 __ | / /__  /_/ /_  /_/ /_____  __ \_  ___/  __ \_  __ \  _ \
 __ |/ / _  ____/_  ____/_____  /_/ /  /   / /_/ /  /_/ /  __/
 _____/  /_/     /_/        _  .___//_/    \____//_.___/\___/ 
                            /_/                               
`

var (
	debugOn bool
)

func init() {
	rootCmd.PersistentFlags().BoolVarP(&debugOn, "debug", "D", os.Getenv("DEBUG") != "", "Enable debug mode")
}

var rootCmd = &cobra.Command{
	Use:     "vpp-probe",
	Short:   "A CLI tool for examining VPP instances",
	Long:    Logo,
	Version: version.Version,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		if debugOn {
			logrus.SetLevel(logrus.DebugLevel)
			logrus.Tracef("debugging enabled")
		}
		return nil
	},
}

func main() {
	_ = rootCmd.Execute()
}
