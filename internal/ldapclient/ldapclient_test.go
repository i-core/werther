package ldapclient

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/pkg/errors"
)

var (
	errBindUser    = fmt.Errorf("bind user error")
	errSearchUser  = fmt.Errorf("search user error")
	errSearchRoles = fmt.Errorf("search user roles error")
	users          = []map[string]interface{}{
		{
			"dn":   "user1",
			"pass": "user1",
			"a":    "valA",
			"b":    "valB",
			"c":    "valC",
		},
		{
			"dn":   "user2",
			"pass": "user2",
			"a":    "valA",
			"b":    "valB",
			"c":    "valC",
			"roles": []map[string]interface{}{
				{"dn": "cn=role1,ou=app1,ou=test,dc=local", "test-roles-attr": "r1"},
				{"dn": "cn=role2,ou=app1,ou=test,dc=local", "test-roles-attr": "r2"},
			},
		},
		{
			"dn":   "user3",
			"pass": "user3",
			"a":    "valA",
			"b":    "valB",
			"c":    "valC",
			"roles": []map[string]interface{}{
				{"dn": "cn=role1,ou=app1,ou=test,dc=local", "test-roles-attr": "r1"},
				{"dn": "cn=role2,ou=app1,ou=test,dc=local", "test-roles-attr": "r2"},
				{"dn": "cn=role3,ou=app2,ou=test,dc=local", "test-roles-attr": "r3"},
				{"dn": "cn=role4,ou=app2,ou=test,dc=local", "test-roles-attr": "r4"},
			},
		},
		{
			"dn":   "user4",
			"pass": "user4",
			"a":    "valA",
			"b":    "valB",
			"c":    "valC",
			"roles": []map[string]interface{}{
				{"dn": "cn=role1,ou=app1,ou=test,dc=local", "test-roles-attr": "r1"},
				{"test-roles-attr": "r2"},
			},
		},
		{
			"dn":   "user5",
			"pass": "user5",
			"a":    "valA",
			"b":    "valB",
			"c":    "valC",
			"roles": []map[string]interface{}{
				{"dn": "cn=role1,ou=app1,ou=test,dc=local", "test-roles-attr": "r1"},
				{"dn": "cn=role2,ou=app1,ou=test,dc=local"},
			},
		},
		{
			"dn":   "user6",
			"pass": "user6",
			"a":    "valA",
			"b":    "valB",
			"c":    "valC",
			"roles": []map[string]interface{}{
				{"dn": "cn=role1,ou=test,dc=local", "test-roles-attr": "r1"},
			},
		},
		{
			"dn":   "serviceUser",
			"pass": "servicePass",
		},
	}
)

func TestAuthenticate(t *testing.T) {
	testCases := []struct {
		name      string
		connector *testConnector
		bindDN    string
		bindPass  string
		user      string
		pass      string
		wantErr   error
		wantAuth  bool
	}{
		{
			name:      "username is empty",
			connector: newTestConnector("ep1", &testConn{users: users}),
		},
		{
			name:      "password is empty",
			connector: newTestConnector("ep1", &testConn{users: users}),
			user:      "user1",
		},
		{
			name:      "connection timeout",
			connector: newTestConnector("ep1", fmt.Errorf("failed to connect to endpoint")),
			user:      "user1",
			pass:      "user1",
			wantErr:   errConnectionTimeout,
		},
		{
			name:      "search user error",
			connector: newTestConnector("ep1", &testConn{userErr: errSearchUser}),
			user:      "user1",
			pass:      "user1",
			wantErr:   errSearchUser,
		},
		{
			name:      "user is not found",
			connector: newTestConnector("ep1", &testConn{}),
			user:      "user1",
			pass:      "user1",
		},
		{
			name:      "authentication error",
			connector: newTestConnector("ep1", &testConn{users: users, bindErr: errBindUser}),
			user:      "user1",
			pass:      "user1",
			wantErr:   errBindUser,
		},
		{
			name:      "invalid password",
			connector: newTestConnector("ep1", &testConn{users: users}),
			user:      "user1",
			pass:      "invalid",
		},
		{
			name:      "success auth",
			connector: newTestConnector("ep1", &testConn{users: users}),
			user:      "user1",
			pass:      "user1",
			wantAuth:  true,
		},
		{
			name:      "auth with invalid service account",
			connector: newTestConnector("ep1", &testConn{users: users}),
			bindDN:    "serviceUser",
			bindPass:  "invalid",
			user:      "user1",
			pass:      "user1",
			wantErr:   errInvalidCredentials,
		},
		{
			name:      "auth with valid service account",
			connector: newTestConnector("ep1", &testConn{users: users}),
			bindDN:    "serviceUser",
			bindPass:  "servicePass",
			user:      "user1",
			pass:      "user1",
			wantAuth:  true,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			client := New(Config{Endpoints: tc.connector.Endpoints(), BindDN: tc.bindDN, BindPass: tc.bindPass})
			client.connector = tc.connector
			ok, err := client.Authenticate(context.Background(), tc.user, tc.pass)

			if ok != tc.wantAuth {
				t.Errorf("got auth: %t, want auth: %t", ok, tc.wantAuth)
			}
			if tc.wantErr != nil {
				if err == nil {
					t.Fatalf("\ngot no errors\nwant error:\n\t%s", tc.wantErr)
				}
				err = errors.Cause(err)
				if err != tc.wantErr {
					t.Fatalf("\ngot error:\n\t%s\nwant error:\n\t%s", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("\ngot error:\n\t%s\nwant no errors", err)
			}
		})
	}
}

func TestAuthenticateWhenMultipleEndpointsFailed(t *testing.T) {
	connector := newTestConnector("ep1", fmt.Errorf("error"), "ep2", fmt.Errorf("error"))
	client := New(Config{Endpoints: connector.Endpoints()})
	client.connector = connector
	_, err := client.Authenticate(context.Background(), "user1", "user1")

	if err == nil {
		t.Fatalf("\ngot no errors\nwant error:\n\t%s", errConnectionTimeout)
	}
	err = errors.Cause(err)
	if err != errConnectionTimeout {
		t.Fatalf("\ngot error:\n\t%s\nwant error:\n\t%s", err, errConnectionTimeout)
	}
}

func TestAuthenticateWhenOneEndpointFailedAndOneSuccess(t *testing.T) {
	ep2 := &testConn{users: users}
	connector := newTestConnector("ep1", fmt.Errorf("error"), "ep2", ep2)
	client := New(Config{Endpoints: connector.Endpoints()})
	client.connector = connector
	ok, err := client.Authenticate(context.Background(), "user1", "user1")

	if err != nil {
		t.Fatalf("\ngot error:\n\t%s\nwant no errors", err)
	}
	if !ok {
		t.Errorf("got auth: %t, want auth: true", ok)
	}
	if !ep2.authRequest {
		t.Error("\ngot: endpoint \"ep2\" is not called, want: endpoint \"ep2\" is called")
	}
}

func TestAuthenticateWhenMultipleEndpointsSuccess(t *testing.T) {
	ep1 := &testConn{users: users}
	ep2 := &testConn{users: users}
	connector := newTestConnector("ep1", ep1, "ep2", ep2)
	client := New(Config{Endpoints: connector.Endpoints()})
	client.connector = connector

	ok, err := client.Authenticate(context.Background(), "user1", "user1")

	// Wait for closing all opened LDAP connections.
	time.Sleep(100 * time.Millisecond)

	if err != nil {
		t.Fatalf("\ngot error:\n\t%s\nwant no errors", err)
	}
	if !ok {
		t.Errorf("got auth: %t, want auth: true", ok)
	}
	switch {
	case ep1.authRequest && ep2.authRequest:
		t.Error("got: every endpoint is called, want: only one endpoint is called")
	case !ep1.authRequest && !ep2.authRequest:
		t.Error("got: no one endpoint is not called, want: only one endpoint is called")
	}
	var notClosed []string
	if !ep1.closed {
		notClosed = append(notClosed, "ep1")
	}
	if !ep2.closed {
		notClosed = append(notClosed, "ep2")
	}
	if len(notClosed) > 0 {
		t.Errorf("got: endpoints %s are not closed, want: all endpoints are closed", strings.Join(notClosed, ", "))
	}
}

func TestFindOIDCClaims(t *testing.T) {
	testCases := []struct {
		name       string
		connector  *testConnector
		bindDN     string
		bindPass   string
		user       string
		attrClaims map[string]string
		wantErr    error
		want       map[string]interface{}
	}{
		{
			name:      "username is empty",
			connector: newTestConnector("ep1", &testConn{users: users}),
			wantErr:   errMissedUsername,
		},
		{
			name:      "connection timeout",
			connector: newTestConnector("ep1", fmt.Errorf("failed to connect to endpoint")),
			user:      "user1",
			wantErr:   errConnectionTimeout,
		},
		{
			name:      "search user error",
			connector: newTestConnector("ep1", &testConn{userErr: errSearchUser}),
			user:      "user1",
			wantErr:   errSearchUser,
		},
		{
			name:      "user is not found",
			connector: newTestConnector("ep1", &testConn{}),
			user:      "user1",
			wantErr:   errUnknownUsername,
		},
		{
			name:      "search roles error",
			connector: newTestConnector("ep1", &testConn{users: users, rolesErr: errSearchRoles}),
			user:      "user1",
			wantErr:   errSearchRoles,
		},
		{
			name:       "extra attributes is filtered from claims",
			connector:  newTestConnector("ep1", &testConn{users: users}),
			user:       "user1",
			attrClaims: map[string]string{"dn": "name", "a": "claimA", "b": "claimB"},
			want:       map[string]interface{}{"name": "user1", "claimA": "valA", "claimB": "valB", "roles": nil},
		},
		{
			name:       "skip claim if no attribute",
			connector:  newTestConnector("ep1", &testConn{users: users}),
			user:       "user1",
			attrClaims: map[string]string{"dn": "name", "a": "claimA", "d": "claimD"},
			want:       map[string]interface{}{"name": "user1", "claimA": "valA", "roles": nil},
		},
		{
			name:       "claims with roles for one application",
			connector:  newTestConnector("ep1", &testConn{users: users}),
			user:       "user2",
			attrClaims: map[string]string{"dn": "name"},
			want:       map[string]interface{}{"name": "user1", "test-roles-claim": map[string][]string{"app1": {"r1", "r2"}}},
		},
		{
			name:       "claims with roles for multiple applications",
			connector:  newTestConnector("ep1", &testConn{users: users}),
			user:       "user3",
			attrClaims: map[string]string{"dn": "name"},
			want:       map[string]interface{}{"name": "user1", "test-roles-claim": map[string][]string{"app1": {"r1", "r2"}, "app2": {"r3", "r4"}}},
		},
		{
			name:       "skip role without DN",
			connector:  newTestConnector("ep1", &testConn{users: users}),
			user:       "user4",
			attrClaims: map[string]string{"dn": "name"},
			want:       map[string]interface{}{"name": "user1", "roles": map[string][]string{"app1": {"r1"}}},
		},
		{
			name:       "skip role without role attribute",
			connector:  newTestConnector("ep1", &testConn{users: users}),
			user:       "user5",
			attrClaims: map[string]string{"dn": "name"},
			want:       map[string]interface{}{"name": "user1", "roles": map[string][]string{"app1": {"r1"}}},
		},
		{
			name:       "skip invalid role without role base DN",
			connector:  newTestConnector("ep1", &testConn{users: users}),
			user:       "user6",
			attrClaims: map[string]string{"dn": "name"},
			want:       map[string]interface{}{"name": "user1", "roles": map[string][]string{"app1": {"r1"}}},
		},
		{
			name:       "auth with invalid service account",
			connector:  newTestConnector("ep1", &testConn{users: users}),
			bindDN:     "serviceUser",
			bindPass:   "invalid",
			user:       "user1",
			attrClaims: map[string]string{"dn": "name", "a": "claimA", "b": "claimB"},
			wantErr:    errInvalidCredentials,
		},
		{
			name:       "auth with valid service account",
			connector:  newTestConnector("ep1", &testConn{users: users}),
			bindDN:     "serviceUser",
			bindPass:   "servicePass",
			user:       "user1",
			attrClaims: map[string]string{"dn": "name", "a": "claimA", "b": "claimB"},
			want:       map[string]interface{}{"name": "user1", "claimA": "valA", "claimB": "valB", "roles": nil},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			client := New(Config{
				Endpoints:  tc.connector.Endpoints(),
				BindDN:     tc.bindDN,
				BindPass:   tc.bindPass,
				AttrClaims: tc.attrClaims,
				RoleBaseDN: "ou=test,dc=local",
				RoleClaim:  "test-roles-claim",
				RoleAttr:   "test-roles-attr",
			})
			client.connector = tc.connector
			got, err := client.FindOIDCClaims(context.Background(), tc.user)

			if tc.wantErr != nil {
				if err == nil {
					t.Fatalf("\ngot no errors\nwant error:\n\t%s", tc.wantErr)
				}
				err = errors.Cause(err)
				if err != tc.wantErr {
					t.Fatalf("\ngot error:\n\t%s\nwant error:\n\t%s", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("\ngot error:\n\t%s\nwant no errors", err)
			}

			if reflect.DeepEqual(got, tc.want) {
				t.Errorf("\ngot claims:\n\t%v\nwant claims:\n\t%v", got, tc.want)
			}
		})
	}
}

func TestClaimsCache(t *testing.T) {
	ep := &testConn{users: users}
	connector := newTestConnector("ep", ep)
	client := New(Config{
		Endpoints:  connector.Endpoints(),
		AttrClaims: map[string]string{"dn": "name", "a": "claimA", "d": "claimD"},
		RoleBaseDN: "ou=test,dc=local",
		RoleClaim:  "test-roles-claim",
		RoleAttr:   "test-roles-attr",
	})
	client.connector = connector

	ok, err := client.Authenticate(context.Background(), "user2", "user2")

	if err != nil {
		t.Fatalf("initial auth: unexpected error: %s", err)
	}
	if !ok {
		t.Fatal("initial auth: got no auth, want auth")
	}

	claims1, err := client.FindOIDCClaims(context.Background(), "user2")

	if err != nil {
		t.Fatalf("claims request 1: unexpected error: %s", err)
	}
	if claims1 == nil {
		t.Fatal("claims request 1: got no claims, want claims")
	}
	if !ep.claimsRequest {
		t.Fatal("claims request 1: got claims from cache, want claims from ldap")
	}

	ep.claimsRequest = false

	claims2, err := client.FindOIDCClaims(context.Background(), "user2")

	if err != nil {
		t.Fatalf("claims request 2: unexpected error: %s", err)
	}
	if claims2 == nil {
		t.Fatal("claims request 2: got no claims, want claims")
	}
	if ep.claimsRequest {
		t.Fatal("claims request 2: got claims from ldap, want claims from cache")
	}
	if !reflect.DeepEqual(claims1, claims2) {
		t.Fatalf("claims request 2:\ngot claims:\n\t%v\nwant claims:\n\t%v", claims2, claims1)
	}

	ok, err = client.Authenticate(context.Background(), "user2", "user2")

	if err != nil {
		t.Fatalf("re-auth: unexpected error: %s", err)
	}
	if !ok {
		t.Fatal("re-auth: got no auth, want auth")
	}

	claims3, err := client.FindOIDCClaims(context.Background(), "user2")

	if err != nil {
		t.Fatalf("claims request 3: unexpected error: %s", err)
	}
	if claims3 == nil {
		t.Fatal("claims request 3: got no claims, want claims")
	}
	if !ep.claimsRequest {
		t.Fatal("claims request 3: got claims from cache, want claims from ldap")
	}
}

type testConnector struct {
	conns map[string]interface{}
}

func newTestConnector(args ...interface{}) *testConnector {
	if len(args)%2 != 0 {
		panic("newTestConnector want args in format \"addr1, conn1, addr2, conn2, addr3, err3\"")
	}
	conns := make(map[string]interface{})
	for i := 0; i < len(args)/2; i++ {
		addr, ok := args[i*2].(string)
		if !ok {
			panic("newTestConnector want args in format \"addr1, conn1, addr2, conn2, addr3, err3\"")
		}

		switch arg := args[i*2+1].(type) {
		case error, *testConn:
			conns[addr] = arg
		default:
			panic("newTestConnector want args in format \"addr1, conn1, addr2, conn2, addr3, err3\"")
		}
	}
	return &testConnector{conns: conns}
}

func (c *testConnector) Endpoints() []string {
	var eps []string
	for addr := range c.conns {
		eps = append(eps, addr)
	}
	return eps
}

func (c *testConnector) Connect(ctx context.Context, addr string) (conn, error) {
	switch v := c.conns[addr].(type) {
	case error:
		return nil, v
	case *testConn:
		return v, nil
	default:
		panic(fmt.Sprintf("Invalid config for endpoint %q", addr))
	}
}

type testConn struct {
	users         []map[string]interface{}
	bindErr       error
	userErr       error
	rolesErr      error
	authRequest   bool
	claimsRequest bool
	closed        bool
}

func (c *testConn) Bind(bindDN, password string) error {
	c.authRequest = true
	if c.bindErr != nil {
		return c.bindErr
	}
	user := c.findUser(bindDN)
	if user == nil {
		return fmt.Errorf("user is not found")
	}
	if user["pass"] != password {
		return errInvalidCredentials
	}
	return nil
}

func (c *testConn) SearchUser(bindDN string, attrs ...string) ([]map[string]interface{}, error) {
	c.claimsRequest = true
	if c.userErr != nil {
		return nil, c.userErr
	}
	user := c.findUser(bindDN)
	if user == nil {
		return nil, nil
	}
	return []map[string]interface{}{user}, nil
}

func (c *testConn) SearchUserRoles(bindDN string, attrs ...string) ([]map[string]interface{}, error) {
	if c.rolesErr != nil {
		return nil, c.rolesErr
	}
	user := c.findUser(bindDN)
	if user == nil {
		return nil, fmt.Errorf("user is not found")
	}
	switch roles := user["roles"].(type) {
	case nil:
		return nil, nil
	case []map[string]interface{}:
		return roles, nil
	default:
		return nil, fmt.Errorf("invalid test roles")
	}
}

func (c *testConn) findUser(bindDN string) map[string]interface{} {
	for _, v := range c.users {
		if v["dn"] == bindDN {
			return v
		}
	}
	return nil
}

func (c *testConn) Close() {
	c.closed = true
}
