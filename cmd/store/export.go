/*
Copyright © 2023 OpenFGA

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package store

import (
	"bytes"
	"context"
	"fmt"
	"github.com/openfga/cli/internal/fga"
	openfga "github.com/openfga/go-sdk"
	"github.com/openfga/go-sdk/client"
	"text/template"
)

type ExportTestCheckResponse struct {
	User       string          `yaml:"user"`
	Object     string          `yaml:"object"`
	Assertions map[string]bool `yaml:"assertions"`
}

type ExportTestResponse struct {
	Name   string                    `yaml:"name"`
	Checks []ExportTestCheckResponse `yaml:"checks"`
}

type ExportTupleResponse struct {
	User     string `yaml:"user"`
	Relation string `yaml:"relation"`
	Object   string `yaml:"object"`
}

type ExportResponse struct {
	Name   string                `yaml:"name"`
	Model  string                `yaml:"model"`
	Tuples []ExportTupleResponse `yaml:"tuples"`
	Tests  []ExportTestResponse  `yaml:"tests"`
}

func readTuples(fgaClient client.SdkClient) ([]openfga.Tuple, error) {
	var (
		tuples            = make([]openfga.Tuple, 0)
		continuationToken = ""
		pageIndex         = 0
		options           = client.ClientReadOptions{}
		body              = &client.ClientReadRequest{}
	)

	for {
		options.ContinuationToken = &continuationToken

		response, err := fgaClient.Read(context.Background()).Body(*body).Options(options).Execute()
		if err != nil {
			return tuples, fmt.Errorf("failed to read tuples due to %w", err)
		}

		tuples = append(tuples, response.Tuples...)
		pageIndex++

		if response.ContinuationToken == "" {
			break
		}

		continuationToken = response.ContinuationToken
	}
	return tuples, nil
}

func renderModelTypesDSL(types []*openfga.TypeDefinition) (string, error) {
	var response bytes.Buffer
	base := `
{{range .Types -}}
{{$rlen := len .Relations -}}
type {{.Name}}
{{if gt $rlen 0 -}}
  relations
    {{range $key, $value := .Relations -}}
    define {{$key}}: {{$value}}
	{{end -}}
{{end -}}
{{end}}`

	type typeDefinition struct {
		Name      string
		Relations map[string]string
	}

	definitions := make([]typeDefinition, len(types))

	for _, t := range types {
		d := typeDefinition{Name: t.GetType()}
		for key, value := range t.GetRelations() {
			
		}
		definitions = append(definitions, d)
	}

	tmpl, err := template.New("types").Parse(base)
	if err != nil {
		return "", err
	}

	return response.String(), nil
}

func exportStore(clientConfig fga.ClientConfig, fgaClient client.SdkClient) (*ExportResponse, error) {
	var (
		err                  error
		store                *client.ClientGetStoreResponse
		model                *openfga.ReadAuthorizationModelResponse
		authorizationModelID = clientConfig.AuthorizationModelID
		tuples               = make([]openfga.Tuple, 0)
	)

	if store, err = fgaClient.GetStore(context.Background()).Execute(); err != nil {
		return nil, fmt.Errorf("failed to export store %v due to %w", clientConfig.StoreID, err)
	}

	if authorizationModelID != "" {
		options := client.ClientReadAuthorizationModelOptions{
			AuthorizationModelId: openfga.PtrString(authorizationModelID),
		}
		model, err = fgaClient.ReadAuthorizationModel(context.Background()).Options(options).Execute()
	} else {
		options := client.ClientReadLatestAuthorizationModelOptions{}
		model, err = fgaClient.ReadLatestAuthorizationModel(context.Background()).Options(options).Execute()
	}

	if err != nil {
		return nil, fmt.Errorf("failed to export store %v due to %w", clientConfig.StoreID, err)
	}

	if tuples, err = readTuples(fgaClient); err != nil {
		return nil, fmt.Errorf("failed to export store %v due to %w", clientConfig.StoreID, err)
	}

	response := &ExportResponse{Name: store.Name}

	var modelTmplBuff bytes.Buffer
	modelTmpl := `|
	model
		schema {{.Schema}}
	{{.Types}}
	{{.Conditions}}`

	var tmpl *template.Template
	tmpl, err = template.New("model").Parse(modelTmpl)
	if err != nil {
		return nil, fmt.Errorf("failed to export store %v due to %w", clientConfig.StoreID, err)
	}

	tmplParams := struct {
		Schema     string
		Types      string
		Conditions string
	}{
		Schema: model.AuthorizationModel.SchemaVersion,
	}

	if err = tmpl.Execute(&modelTmplBuff, tmplParams); err != nil {
		return nil, fmt.Errorf("failed to export store %v due to %w", clientConfig.StoreID, err)
	}
	response.Model = modelTmplBuff.String()

	return response, nil
}
