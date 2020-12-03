// Copyright 2018 The casbin Authors. All Rights Reserved.
//
// Copyright 2020 Southbank Software Pty Ltd. All Rights Reserved.
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
	"fmt"
	"os"
	"testing"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/util"
	"go.mongodb.org/mongo-driver/bson"
)

var testDbURL = os.Getenv("TEST_MONGODB_URL")

func getDbURL() string {
	if testDbURL == "" {
		testDbURL = "127.0.0.1:27017"
	}
	return testDbURL
}

// Setup performs initialization of a fresh dataset for testing.
// - data should be an array of CasbinRule, as that is the document representation in Mongo
// for a rule. This ensures data in Mongo is exactly how we would expect to see it.
func setup(a *adapter, data []interface{}) {
	if len(data) != 0 {
		_, err := a.collection.InsertMany(context.TODO(), data)
		if err != nil {
			panic(err)
		}
	}
}

// setupRBAC performs setup of test data using the model from examples/rbac_model.conf
func setupRBAC(a *adapter) {
	setup(a, []interface{}{
		CasbinRule{nil, "p", "alice", "data1", "read", "", "", ""},
		CasbinRule{nil, "p", "bob", "data2", "write", "", "", ""},
		CasbinRule{nil, "p", "data2_admin", "data2", "read", "", "", ""},
		CasbinRule{nil, "p", "data2_admin", "data2", "write", "", "", ""},
		CasbinRule{nil, "g", "alice", "data2_admin", "", "", "", ""},
	})
}

// setupRBACTenancy performs setup of test data using the model from examples/rbac_tenant_service.conf
func setupRBACTenancy(a *adapter) {
	setup(a, []interface{}{
		CasbinRule{nil, "p", "domain1", "alice", "data3", "read", "accept", "service1"},
		CasbinRule{nil, "p", "domain1", "alice", "data3", "write", "accept", "service2"},
	})
}

// Teardown performs deletion of test data for clean up.
func teardown(a *adapter) {
	// Delete all the casbin_rule collection data
	_, err := a.collection.DeleteMany(context.TODO(), bson.D{})
	if err != nil {
		panic(err)
	}
}

func compare(expected CasbinRule, actual CasbinRule) bool {
	return expected == actual
}

func testGetPolicy(t *testing.T, e *casbin.Enforcer, res [][]string) {
	t.Helper()
	myRes := e.GetPolicy()
	t.Log("Policy: ", myRes)

	if !util.Array2DEquals(res, myRes) {
		t.Error("Policy: ", myRes, ", supposed to be ", res)
	}
}

func TestAdapter(t *testing.T) {
	// Now the DB has policy, so we can provide a normal use case.
	// Create an adapter and an enforcer.
	// NewEnforcer() will load the policy automatically.
	a, err := NewAdapter(getDbURL())
	if err != nil {
		panic(err)
	}

	// Get the Mongo adapter implementation so we have access to the client
	ma := a.(*adapter)

	// Setup to populate our test data
	setupRBAC(ma)
	defer teardown(ma)

	e, err := casbin.NewEnforcer("examples/rbac_model.conf", a)
	if err != nil {
		panic(err)
	}
	testGetPolicy(t, e, [][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}})

	// AutoSave is enabled by default.
	// Now we disable it.
	e.EnableAutoSave(false)

	// Because AutoSave is disabled, the policy change only affects the policy in Casbin enforcer,
	// it doesn't affect the policy in the storage.
	e.AddPolicy("alice", "data1", "write")
	// Reload the policy from the storage to see the effect.
	if err := e.LoadPolicy(); err != nil {
		t.Errorf("Expected LoadPolicy() to be successful; got %v", err)
	}
	// This is still the original policy.
	testGetPolicy(t, e, [][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}})

	// Now we enable the AutoSave.
	e.EnableAutoSave(true)

	// Because AutoSave is enabled, the policy change not only affects the policy in Casbin enforcer,
	// but also affects the policy in the storage.
	e.AddPolicy("alice", "data1", "write")
	// Reload the policy from the storage to see the effect.
	if err := e.LoadPolicy(); err != nil {
		t.Errorf("Expected LoadPolicy() to be successful; got %v", err)
	}
	// The policy has a new rule: {"alice", "data1", "write"}.
	testGetPolicy(t, e, [][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}, {"alice", "data1", "write"}})

	// Remove the added rule.
	e.RemovePolicy("alice", "data1", "write")
	if err := a.RemovePolicy("p", "p", []string{"alice", "data1", "write"}); err != nil {
		t.Errorf("Expected RemovePolicy() to be successful; got %v", err)
	}
	if err := e.LoadPolicy(); err != nil {
		t.Errorf("Expected LoadPolicy() to be successful; got %v", err)
	}
	testGetPolicy(t, e, [][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}})

	// Remove "data2_admin" related policy rules via a filter.
	// Two rules: {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"} are deleted.
	e.RemoveFilteredPolicy(0, "data2_admin")
	if err := e.LoadPolicy(); err != nil {
		t.Errorf("Expected LoadPolicy() to be successful; got %v", err)
	}
	testGetPolicy(t, e, [][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}})

	e.RemoveFilteredPolicy(1, "data1")
	if err := e.LoadPolicy(); err != nil {
		t.Errorf("Expected LoadPolicy() to be successful; got %v", err)
	}
	testGetPolicy(t, e, [][]string{{"bob", "data2", "write"}})

	e.RemoveFilteredPolicy(2, "write")
	if err := e.LoadPolicy(); err != nil {
		t.Errorf("Expected LoadPolicy() to be successful; got %v", err)
	}
	testGetPolicy(t, e, [][]string{})
}

func TestDeleteFilteredAdapter(t *testing.T) {
	a, err := NewAdapter(getDbURL())
	if err != nil {
		panic(err)
	}

	// Get the Mongo adapter implementation so we have access to the client
	ma := a.(*adapter)

	// Setup to populate our test data
	setupRBACTenancy(ma)
	defer teardown(ma)

	e, err := casbin.NewEnforcer("examples/rbac_tenant_service.conf", a)
	if err != nil {
		panic(err)
	}
	// Reload the policy from the storage to see the effect.
	if err := e.LoadPolicy(); err != nil {
		t.Errorf("Expected LoadPolicy() to be successful; got %v", err)
	}
	// The policy has a new rule: {"alice", "data1", "write"}.
	testGetPolicy(t, e, [][]string{{"domain1", "alice", "data3", "read", "accept", "service1"},
		{"domain1", "alice", "data3", "write", "accept", "service2"}})
	// test RemoveFiltered Policy with "" fileds
	e.RemoveFilteredPolicy(0, "domain1", "", "", "read")
	if err := e.LoadPolicy(); err != nil {
		t.Errorf("Expected LoadPolicy() to be successful; got %v", err)
	}
	testGetPolicy(t, e, [][]string{{"domain1", "alice", "data3", "write", "accept", "service2"}})

	e.RemoveFilteredPolicy(0, "domain1", "", "", "", "", "service2")
	if err := e.LoadPolicy(); err != nil {
		t.Errorf("Expected LoadPolicy() to be successful; got %v", err)
	}
	testGetPolicy(t, e, [][]string{})
}

func TestFilteredAdapter(t *testing.T) {
	// Now the DB has policy, so we can provide a normal use case.
	// Create an adapter and an enforcer.
	// NewEnforcer() will load the policy automatically.
	a, err := NewFilteredAdapter(getDbURL())
	if err != nil {
		panic(err)
	}

	// Get the Mongo adapter implementation so we have access to the client
	ma := a.(*adapter)

	// Setup to populate our test data
	setup(ma, []interface{}{
		CasbinRule{nil, "p", "alice", "data1", "write", "", "", ""},
		CasbinRule{nil, "p", "bob", "data2", "write", "", "", ""},
	})
	defer teardown(ma)

	e, err := casbin.NewEnforcer("examples/rbac_model.conf", a)
	if err != nil {
		panic(err)
	}

	// Reload the filtered policy from the storage.
	filter := &bson.M{"v0": "bob"}
	if err := e.LoadFilteredPolicy(filter); err != nil {
		t.Errorf("Expected LoadFilteredPolicy() to be successful; got %v", err)
	}
	// Only bob's policy should have been loaded
	testGetPolicy(t, e, [][]string{{"bob", "data2", "write"}})

	// Verify that alice's policy remains intact in the database.
	filter = &bson.M{"v0": "alice"}
	if err := e.LoadFilteredPolicy(filter); err != nil {
		t.Errorf("Expected LoadFilteredPolicy() to be successful; got %v", err)
	}
	// Only alice's policy should have been loaded,
	testGetPolicy(t, e, [][]string{{"alice", "data1", "write"}})

	// Test safe handling of SavePolicy when using filtered policies.
	if err := e.SavePolicy(); err == nil {
		t.Errorf("Expected SavePolicy() to fail for a filtered policy")
	}
	if err := e.LoadPolicy(); err != nil {
		t.Errorf("Expected LoadPolicy() to be successful; got %v", err)
	}
	if err := e.SavePolicy(); err != nil {
		t.Errorf("Expected SavePolicy() to be successful; got %v", err)
	}

	e.RemoveFilteredPolicy(2, "write")
	if err := e.LoadPolicy(); err != nil {
		t.Errorf("Expected LoadPolicy() to be successful; got %v", err)
	}
	testGetPolicy(t, e, [][]string{})
}

func TestUpdatableAdapter_UpdatePolicy(t *testing.T) {
	// Create the new adapter
	a, err := NewUpdatableAdapter(getDbURL())
	if err != nil {
		panic(err)
	}
	// Get the Mongo adapter implementation so we have access to the client
	ma := a.(*adapter)

	// Setup to populate our test data
	setupRBAC(ma)
	defer teardown(ma)

	// Get the stored document to be updated before running the test
	filter := &CasbinRule{
		PType: "p",
		V0:    "alice",
		V1:    "data1",
		V2:    "read",
	}

	var before *CasbinRule
	if err := ma.collection.FindOne(context.TODO(), filter).Decode(&before); err != nil {
		t.Fatal(err)
	}
	// Modify the rule to allow 'write' access and
	oldRule := []string{"alice", "data1", "read"}
	newRule := []string{"alice", "data1", "write"}
	if err := a.UpdatePolicy("ignored", "p", oldRule, newRule); err != nil {
		t.Fatal(err)
	}
	// Check database and ensure document has been updated. We can use the ID to find.
	// If no result, ID has been changed which should fail. Updates in Mongo don't affect
	// the _id.
	var actual *CasbinRule
	if err := ma.collection.FindOne(context.TODO(), bson.M{"_id": before.ID}).Decode(&actual); err != nil {
		t.Fatal(err)
	}

	expected := &CasbinRule{
		ID:    before.ID,
		PType: before.PType,
		V0:    "alice",
		V1:    "data1",
		V2:    "write",
		V3:    "",
		V4:    "",
		V5:    "",
	}

	if !compare(*expected, *actual) {
		t.Fatal("expected does not match actual")
	}
}

func TestFilteredAdapter_UpdatePolicy(t *testing.T) {
	// Create the new adapter (not updatable)
	a, err := NewFilteredAdapter(getDbURL())
	if err != nil {
		panic(err)
	}
	// Get the Mongo adapter implementation so we have access to the client
	ma := a.(*adapter)

	// Setup to populate our test data
	setupRBAC(ma)
	defer teardown(ma)

	oldRule := []string{"alice", "data1", "read"}
	newRule := []string{"alice", "data2", "write"}
	// This should fail because we haven't initialized with NewUpdatableAdapter
	if err := ma.UpdatePolicy("ignored", "p", oldRule, newRule); err == nil {
		t.Fatal("UpdatePolicy should not have been allowed")
	}
}

func TestAdapter_UpdatePolicy(t *testing.T) {
	// Create the new adapter (not updatable)
	a, err := NewAdapter(getDbURL())
	if err != nil {
		panic(err)
	}
	// Get the Mongo adapter implementation so we have access to the client
	ma := a.(*adapter)

	// Setup to populate our test data
	setupRBAC(ma)
	defer teardown(ma)

	oldRule := []string{"alice", "data1", "read"}
	newRule := []string{"alice", "data2", "write"}
	// This should fail because we haven't initialized with NewUpdatableAdapter
	if err := ma.UpdatePolicy("ignored", "p", oldRule, newRule); err == nil {
		t.Fatal("UpdatePolicy should not have been allowed")
	}
}

func TestNewAdapterWithInvalidURL(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("Expected recovery from panic")
		}
	}()

	_, err := NewAdapter("localhost:40001?foo=1&bar=2")
	if err != nil {
		panic(err)
	}
}

func TestNewAdapterWithUnknownURL(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("Expected recovery from panic")
		}
	}()

	_, err := NewAdapter("fakeserver:27017")
	if err != nil {
		panic(err)
	}
}

func TestNewAdapterWithDatabase(t *testing.T) {
	_, err := NewAdapter(fmt.Sprint(getDbURL() + "/abc"))
	if err != nil {
		panic(err)
	}
}
