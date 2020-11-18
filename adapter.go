// Copyright 2018 The casbin Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package mongodbadapter

import (
	"context"
	"errors"
	"fmt"
	neturl "net/url"
	"runtime"
	"strings"
	"time"

	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/x/bsonx"
)

const defaultTimeout time.Duration = 30 * time.Second

// CasbinRule represents a rule in Casbin.
type CasbinRule struct {
	ID    interface{} `bson:"_id,omitempty"`
	PType string      `bson:"ptype"`
	V0    string      `bson:"v0"`
	V1    string      `bson:"v1"`
	V2    string      `bson:"v2"`
	V3    string      `bson:"v3"`
	V4    string      `bson:"v4"`
	V5    string      `bson:"v5"`
}

// adapter represents the MongoDB adapter for policy storage.
type adapter struct {
	clientOption *options.ClientOptions
	client       *mongo.Client
	collection   *mongo.Collection
	timeout      time.Duration
	updatable    bool
	filtered     bool
}

// finalizer is the destructor for adapter.
func finalizer(a *adapter) {
	a.close()
}

// NewAdapter is the constructor for Adapter. If database name is not provided
// in the Mongo URL, 'casbin' will be used as database name.
func NewAdapter(url string, timeout ...interface{}) (persist.Adapter, error) {
	if !strings.HasPrefix(url, "mongodb+srv://") && !strings.HasPrefix(url, "mongodb://") {
		url = fmt.Sprint("mongodb://" + url)
	}
	clientOption := options.Client().ApplyURI(url)

	u, err := neturl.Parse(url)
	if err != nil {
		return nil, err
	}

	var databaseName string
	if u.Path != "" {
		databaseName = u.Path[1:]
	} else {
		databaseName = "casbin_rule"
	}

	return NewAdapterWithClientOption(clientOption, databaseName, timeout...)
}

// NewAdapterWithClientOption is an alternative constructor for Adapter
// that does the same as NewAdapter, but uses mongo.ClientOption instead of a Mongo URL
func NewAdapterWithClientOption(clientOption *options.ClientOptions, databaseName string, timeout ...interface{}) (persist.Adapter, error) {
	a := &adapter{
		clientOption: clientOption,
	}
	a.filtered = false

	if len(timeout) == 1 {
		a.timeout = timeout[0].(time.Duration)
	} else if len(timeout) > 1 {
		return nil, errors.New("too many arguments")
	} else {
		a.timeout = defaultTimeout
	}

	// Open the DB, create it if not existed.
	err := a.open(databaseName)
	if err != nil {
		return nil, err
	}

	// Call the destructor when the object is released.
	runtime.SetFinalizer(a, finalizer)

	return a, nil
}

// NewFilteredAdapter is the constructor for FilteredAdapter.
// Casbin will not automatically call LoadPolicy() for a filtered adapter.
func NewFilteredAdapter(url string) (persist.FilteredAdapter, error) {
	a, err := NewAdapter(url)
	if err != nil {
		return nil, err
	}
	a.(*adapter).filtered = true

	return a.(*adapter), nil
}

// NewUpdatableAdapter is the constructor for an UpdatableAdapter. It is the standard Adapter, with
// ability to update a single policy. If database name is not provided in the Mongo URL, 'casbin' will
// be used as database name.
func NewUpdatableAdapter(url string, timeout ...interface{}) (persist.UpdatableAdapter, error) {
	a, err := NewAdapter(url, timeout...)
	if err != nil {
		return nil, err
	}
	a.(*adapter).updatable = true

	return a.(*adapter), nil
}

// NewUpdatableAdapterWithClientOption is an alternative constructor for UpdatableAdapter
// that does the same as NewUpdatableAdapter, but uses mongo.ClientOption instead of a Mongo URL
func NewUpdatableAdapterWithClientOption(clientOption *options.ClientOptions, databaseName string, timeout ...interface{}) (persist.UpdatableAdapter, error) {
	a, err := NewAdapterWithClientOption(clientOption, databaseName, timeout...)
	if err != nil {
		return nil, err
	}
	a.(*adapter).updatable = true

	return a.(*adapter), nil
}

func (a *adapter) open(databaseName string) error {
	ctx, cancel := context.WithTimeout(context.TODO(), a.timeout)
	defer cancel()

	client, err := mongo.Connect(ctx, a.clientOption)
	if err != nil {
		return err
	}

	db := client.Database(databaseName)
	collection := db.Collection("casbin_rule")

	a.client = client
	a.collection = collection

	indexes := []string{"ptype", "v0", "v1", "v2", "v3", "v4", "v5"}
	keysDoc := bsonx.Doc{}

	for _, k := range indexes {
		keysDoc = keysDoc.Append(k, bsonx.Int32(1))
	}

	if _, err = collection.Indexes().CreateOne(
		context.Background(),
		mongo.IndexModel{
			Keys:    keysDoc,
			Options: options.Index().SetUnique(true),
		},
	); err != nil {
		return err
	}

	return nil
}

func (a *adapter) close() {
	ctx, cancel := context.WithTimeout(context.TODO(), a.timeout)
	defer cancel()
	a.client.Disconnect(ctx)
}

func (a *adapter) dropTable() error {
	ctx, cancel := context.WithTimeout(context.TODO(), a.timeout)
	defer cancel()

	err := a.collection.Drop(ctx)
	if err != nil {
		return err
	}
	return nil
}

func loadPolicyLine(line CasbinRule, model model.Model) {
	var p = []string{line.PType,
		line.V0, line.V1, line.V2, line.V3, line.V4, line.V5}
	var lineText string
	if line.V5 != "" {
		lineText = strings.Join(p, ", ")
	} else if line.V4 != "" {
		lineText = strings.Join(p[:6], ", ")
	} else if line.V3 != "" {
		lineText = strings.Join(p[:5], ", ")
	} else if line.V2 != "" {
		lineText = strings.Join(p[:4], ", ")
	} else if line.V1 != "" {
		lineText = strings.Join(p[:3], ", ")
	} else if line.V0 != "" {
		lineText = strings.Join(p[:2], ", ")
	}

	persist.LoadPolicyLine(lineText, model)
}

// LoadPolicy loads policy from database.
func (a *adapter) LoadPolicy(model model.Model) error {
	return a.LoadFilteredPolicy(model, nil)
}

// LoadFilteredPolicy loads matching policy lines from database. If not nil,
// the filter must be a valid MongoDB selector.
func (a *adapter) LoadFilteredPolicy(model model.Model, filter interface{}) error {
	if filter == nil {
		a.filtered = false
		filter = bson.D{{}}
	} else {
		a.filtered = true
	}
	line := CasbinRule{}

	ctx, cancel := context.WithTimeout(context.TODO(), a.timeout)
	defer cancel()

	cursor, err := a.collection.Find(ctx, filter)
	if err != nil {
		return err
	}

	for cursor.Next(ctx) {
		err := cursor.Decode(&line)
		if err != nil {
			return err
		}
		loadPolicyLine(line, model)
	}

	return cursor.Close(ctx)
}

// IsFiltered returns true if the loaded policy has been filtered.
func (a *adapter) IsFiltered() bool {
	return a.filtered
}

func savePolicyLine(ptype string, rule []string) CasbinRule {
	line := CasbinRule{
		PType: ptype,
	}

	if len(rule) > 0 {
		line.V0 = rule[0]
	}
	if len(rule) > 1 {
		line.V1 = rule[1]
	}
	if len(rule) > 2 {
		line.V2 = rule[2]
	}
	if len(rule) > 3 {
		line.V3 = rule[3]
	}
	if len(rule) > 4 {
		line.V4 = rule[4]
	}
	if len(rule) > 5 {
		line.V5 = rule[5]
	}

	return line
}

// SavePolicy saves policy to database.
func (a *adapter) SavePolicy(model model.Model) error {
	if a.filtered {
		return errors.New("cannot save a filtered policy")
	}
	if err := a.dropTable(); err != nil {
		return err
	}

	var lines []interface{}

	for ptype, ast := range model["p"] {
		for _, rule := range ast.Policy {
			line := savePolicyLine(ptype, rule)
			lines = append(lines, &line)
		}
	}

	for ptype, ast := range model["g"] {
		for _, rule := range ast.Policy {
			line := savePolicyLine(ptype, rule)
			lines = append(lines, &line)
		}
	}
	ctx, cancel := context.WithTimeout(context.TODO(), a.timeout)
	defer cancel()

	if _, err := a.collection.InsertMany(ctx, lines); err != nil {
		return err
	}

	return nil
}

// AddPolicy adds a policy rule to the storage.
func (a *adapter) AddPolicy(sec string, ptype string, rule []string) error {
	line := savePolicyLine(ptype, rule)

	ctx, cancel := context.WithTimeout(context.TODO(), a.timeout)
	defer cancel()

	if _, err := a.collection.InsertOne(ctx, line); err != nil {
		return err
	}

	return nil
}

// RemovePolicy removes a policy rule from the storage.
func (a *adapter) RemovePolicy(sec string, ptype string, rule []string) error {
	line := savePolicyLine(ptype, rule)

	ctx, cancel := context.WithTimeout(context.TODO(), a.timeout)
	defer cancel()

	if _, err := a.collection.DeleteOne(ctx, line); err != nil {
		return err
	}

	return nil
}

// RemoveFilteredPolicy removes policy rules that match the filter from the storage.
func (a *adapter) RemoveFilteredPolicy(sec string, ptype string, fieldIndex int, fieldValues ...string) error {
	selector := make(map[string]interface{})
	selector["ptype"] = ptype

	if fieldIndex <= 0 && 0 < fieldIndex+len(fieldValues) {
		if fieldValues[0-fieldIndex] != "" {
			selector["v0"] = fieldValues[0-fieldIndex]
		}
	}
	if fieldIndex <= 1 && 1 < fieldIndex+len(fieldValues) {
		if fieldValues[1-fieldIndex] != "" {
			selector["v1"] = fieldValues[1-fieldIndex]
		}
	}
	if fieldIndex <= 2 && 2 < fieldIndex+len(fieldValues) {
		if fieldValues[2-fieldIndex] != "" {
			selector["v2"] = fieldValues[2-fieldIndex]
		}
	}
	if fieldIndex <= 3 && 3 < fieldIndex+len(fieldValues) {
		if fieldValues[3-fieldIndex] != "" {
			selector["v3"] = fieldValues[3-fieldIndex]
		}
	}
	if fieldIndex <= 4 && 4 < fieldIndex+len(fieldValues) {
		if fieldValues[4-fieldIndex] != "" {
			selector["v4"] = fieldValues[4-fieldIndex]
		}
	}
	if fieldIndex <= 5 && 5 < fieldIndex+len(fieldValues) {
		if fieldValues[5-fieldIndex] != "" {
			selector["v5"] = fieldValues[5-fieldIndex]
		}
	}

	ctx, cancel := context.WithTimeout(context.TODO(), a.timeout)
	defer cancel()

	if _, err := a.collection.DeleteMany(ctx, selector); err != nil {
		return err
	}

	return nil
}

// UpdatePolicy updates a policy rule from storage.
func (a *adapter) UpdatePolicy(sec string, ptype string, oldRule, newPolicy []string) error {
	// NewUpdatableAdapter must be used for this function to be allowed
	if !a.updatable {
		return errors.New("cannot save updated policy")
	}
	filter := savePolicyLine(ptype, oldRule)
	update := savePolicyLine(ptype, newPolicy)

	ctx, cancel := context.WithTimeout(context.TODO(), a.timeout)
	defer cancel()

	if _, err := a.collection.UpdateOne(ctx, filter, bson.D{{Key: "$set", Value: update}}); err != nil {
		return err
	}

	return nil
}
