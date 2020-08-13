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

	"github.com/spf13/cobra"

	"go.ligato.io/vpp-probe/version"
)

const Logo = `
                                                    ______       
 ___   _________________       ________________________  /______ 
 __ | / /__  __ \__  __ \_________  __ \_  ___/  __ \_  __ \  _ \
 __ |/ /__  /_/ /_  /_/ //_____/_  /_/ /  /   / /_/ /  /_/ /  __/
 _____/ _  .___/_  .___/       _  .___//_/    \____//_.___/\___/ 
        /_/     /_/            /_/                               
`

var (
	debugOn bool
)

func init() {
	rootCmd.PersistentFlags().BoolVarP(&debugOn, "debug", "D", os.Getenv("DEBUG") != "", "Enable debug mode")
}

var rootCmd = &cobra.Command{
	Use:     "vpp-probe",
	Short:   "A CLI tool for probing VPP instances",
	Long:    Logo,
	Version: version.Version,
}

func main() {
	_ = rootCmd.Execute()
}
