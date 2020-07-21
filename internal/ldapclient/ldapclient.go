/*
Copyright (c) JSC iCore.

This source code is licensed under the MIT license found in the
LICENSE file in the root directory of this source tree.
*/

package ldapclient

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/coocood/freecache"
	"github.com/go-ldap/ldap/v3"
	"github.com/i-core/rlog"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

var (
	// errInvalidCredentials is an error that happens when a user's password is invalid.
	errInvalidCredentials = fmt.Errorf("invalid credentials")
	// errConnectionTimeout is an error that happens when no one LDAP endpoint responds.
	errConnectionTimeout = fmt.Errorf("connection timeout")
	// errMissedUsername is an error that happens
	errMissedUsername = errors.New("username is missed")
	// errUnknownUsername is an error that happens
	errUnknownUsername = errors.New("unknown username")
)

type conn interface {
	Bind(bindDN, password string) error
	SearchUser(user string, attrs ...string) ([]map[string]interface{}, error)
	SearchUserRoles(user string, attrs ...string) ([]map[string]interface{}, error)
	Close()
}

type connector interface {
	Connect(ctx context.Context, addr string) (conn, error)
}

// Config is a LDAP configuration.
type Config struct {
	Endpoints  []string          `envconfig:"endpoints" required:"true" desc:"a LDAP's server URLs as \"<address>:<port>\""`
	BindDN     string            `envconfig:"binddn" desc:"a LDAP bind DN"`
	BindPass   string            `envconfig:"bindpw" json:"-" desc:"a LDAP bind password"`
	BaseDN     string            `envconfig:"basedn" required:"true" desc:"a LDAP base DN for searching users"`
	AttrClaims map[string]string `envconfig:"attr_claims" default:"name:name,sn:family_name,givenName:given_name,mail:email" desc:"a mapping of LDAP attributes to OpenID connect claims"`
	RoleBaseDN string            `envconfig:"role_basedn" required:"true" desc:"a LDAP base DN for searching roles"`
	RoleAttr   string            `envconfig:"role_attr" default:"description" desc:"a LDAP group's attribute that contains a role's name"`
	RoleClaim  string            `envconfig:"role_claim" default:"https://github.com/i-core/werther/claims/roles" desc:"a name of an OpenID Connect claim that contains user roles"`
	CacheSize  int               `envconfig:"cache_size" default:"512" desc:"a user info cache's size in KiB"`
	CacheTTL   time.Duration     `envconfig:"cache_ttl" default:"30m" desc:"a user info cache TTL"`
	IsTLS      bool              `envconfig:"is_tls" default:"false" desc:"should LDAP connection be established via TLS"`
}

// Client is a LDAP client (compatible with Active Directory).
type Client struct {
	Config
	connector connector
	cache     *freecache.Cache
}

// New creates a new LDAP client.
func New(cnf Config) *Client {
	return &Client{
		Config:    cnf,
		connector: &ldapConnector{BaseDN: cnf.BaseDN, RoleBaseDN: cnf.RoleBaseDN, IsTLS: cnf.IsTLS},
		cache:     freecache.NewCache(cnf.CacheSize * 1024),
	}
}

// Authenticate authenticates a user with a username and password.
// If no username or password in LDAP it returns false and no error.
func (cli *Client) Authenticate(ctx context.Context, username, password string) (bool, error) {
	if username == "" || password == "" {
		return false, nil
	}

	var cancel context.CancelFunc
	ctx, cancel = context.WithCancel(ctx)

	cn, ok := <-cli.connect(ctx)
	cancel()
	if !ok {
		return false, errConnectionTimeout
	}
	defer cn.Close()

	// Find a user DN by his or her username.
	details, err := cli.findBasicUserDetails(cn, username, []string{"dn"})
	if err != nil {
		return false, err
	}
	if details == nil {
		return false, nil
	}

	if err := cn.Bind(details["dn"].(string), password); err != nil {
		if err == errInvalidCredentials {
			return false, nil
		}
		return false, err
	}

	// Clear the claims' cache because of possible re-authentication. We don't want stale claims after re-login.
	if ok := cli.cache.Del([]byte(username)); ok {
		log := rlog.FromContext(ctx)
		log.Debug("Cleared user's OIDC claims in the cache")
	}

	return true, nil
}

// FindOIDCClaims finds all OIDC claims for a user.
func (cli *Client) FindOIDCClaims(ctx context.Context, username string) (map[string]interface{}, error) {
	if username == "" {
		return nil, errMissedUsername
	}

	log := rlog.FromContext(ctx).Sugar()

	// Retrieving from LDAP is slow. So, we try to get claims for the given username from the cache.
	switch cdata, err := cli.cache.Get([]byte(username)); err {
	case nil:
		var claims map[string]interface{}
		if err = json.Unmarshal(cdata, &claims); err != nil {
			log.Info("Failed to unmarshal user's OIDC claims", zap.Error(err), "data", cdata)
			return nil, err
		}
		log.Debug("Retrieved user's OIDC claims from the cache", "claims", claims)
		return claims, nil
	case freecache.ErrNotFound:
		log.Debug("User's OIDC claims is not found in the cache")
	default:
		log.Infow("Failed to retrieve user's OIDC claims from the cache", zap.Error(err))
	}

	// Try to make multiple TCP connections to the LDAP server for getting claims.
	// Accept the first one, and cancel others.
	var cancel context.CancelFunc
	ctx, cancel = context.WithCancel(ctx)

	cn, ok := <-cli.connect(ctx)
	cancel()
	if !ok {
		return nil, errConnectionTimeout
	}
	defer cn.Close()

	// We need to find LDAP attribute's names for all required claims.
	attrs := []string{"dn"}
	for k := range cli.AttrClaims {
		attrs = append(attrs, k)
	}
	// Find the attributes in the LDAP server.
	details, err := cli.findBasicUserDetails(cn, username, attrs)
	if err != nil {
		return nil, err
	}
	if details == nil {
		return nil, errUnknownUsername
	}
	log.Infow("Retrieved user's info from LDAP", "details", details)

	// Transform the retrieved attributes to corresponding claims.
	claims := make(map[string]interface{})
	for attr, v := range details {
		if claim, ok := cli.AttrClaims[attr]; ok {
			claims[claim] = v
		}
	}

	// User's roles is stored in LDAP as groups. We find all groups in a role's DN
	// that include the user as a member.
	entries, err := cn.SearchUserRoles(fmt.Sprintf("%s", details["dn"]), "dn", cli.RoleAttr)
	if err != nil {
		return nil, err
	}

	roles := make(map[string]interface{})
	for _, entry := range entries {
		roleDN, ok := entry["dn"].(string)
		if !ok || roleDN == "" {
			log.Infow("No required LDAP attribute for a role", "ldapAttribute", "dn", "entry", entry)
			continue
		}
		if entry[cli.RoleAttr] == nil {
			log.Infow("No required LDAP attribute for a role", "ldapAttribute", cli.RoleAttr, "roleDN", roleDN)
			continue
		}

		// Ensure that a role's DN is inside of the role's base DN.
		// It's sufficient to compare the DN's suffix with the base DN.
		n, k := len(roleDN), len(cli.RoleBaseDN)
		if n < k || !strings.EqualFold(roleDN[n-k:], cli.RoleBaseDN) {
			panic("You should never see that")
		}
		// The DN without the role's base DN must contain a CN and OU
		// where the CN is for uniqueness only, and the OU is an application id.
		path := strings.Split(roleDN[:n-k-1], ",")
		if len(path) != 2 {
			log.Infow("A role's DN without the role's base DN must contain two nodes only",
				"roleBaseDN", cli.RoleBaseDN, "roleDN", roleDN)
			continue
		}
		appID := path[1][len("OU="):]

		var appRoles []interface{}
		if v := roles[appID]; v != nil {
			appRoles = v.([]interface{})
		}
		roles[appID] = append(appRoles, entry[cli.RoleAttr])
	}
	claims[cli.RoleClaim] = roles

	// Save the claims in the cache for future queries.
	cdata, err := json.Marshal(claims)
	if err != nil {
		log.Infow("Failed to marshal user's OIDC claims for caching", zap.Error(err), "claims", claims)
	}
	if err = cli.cache.Set([]byte(username), cdata, int(cli.CacheTTL.Seconds())); err != nil {
		log.Infow("Failed to store user's OIDC claims into the cache", zap.Error(err), "claims", claims)
	}

	return claims, nil
}

func (cli *Client) connect(ctx context.Context) <-chan conn {
	var (
		wg sync.WaitGroup
		ch = make(chan conn)
	)
	wg.Add(len(cli.Endpoints))
	for _, addr := range cli.Endpoints {
		go func(addr string) {
			defer wg.Done()

			log := rlog.FromContext(ctx).Sugar()
			cn, err := cli.connector.Connect(ctx, addr)
			if err != nil {
				log.Debug("Failed to create a LDAP connection", "address", addr)
				return
			}
			select {
			case <-ctx.Done():
				cn.Close()
				log.Debug("a LDAP connection is cancelled", "address", addr)
				return
			case ch <- cn:
			}
		}(addr)
	}
	go func() {
		wg.Wait()
		close(ch)
	}()
	return ch
}

// findBasicUserDetails finds user's LDAP attributes that were specified. It returns nil if no such user.
func (cli *Client) findBasicUserDetails(cn conn, username string, attrs []string) (map[string]interface{}, error) {
	if cli.BindDN != "" {
		// We need to login to a LDAP server with a service account for retrieving user data.
		if err := cn.Bind(cli.BindDN, cli.BindPass); err != nil {
			return nil, errors.Wrap(err, "failed to login to a LDAP woth a service account")
		}
	}

	entries, err := cn.SearchUser(username, attrs...)
	if err != nil {
		return nil, err
	}
	if len(entries) != 1 {
		// We didn't find the user.
		return nil, nil
	}

	var (
		entry   = entries[0]
		details = make(map[string]interface{})
	)
	for _, attr := range attrs {
		if v, ok := entry[attr]; ok {
			details[attr] = v
		}
	}
	return details, nil
}

type ldapConnector struct {
	BaseDN     string
	RoleBaseDN string
	IsTLS      bool
}

func (c *ldapConnector) Connect(ctx context.Context, addr string) (conn, error) {
	d := net.Dialer{Timeout: ldap.DefaultTimeout}
	tcpcn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}

	if c.IsTLS {
		tlscn, err := tls.DialWithDialer(&d, "tcp", addr, nil)
		if err != nil {
			return nil, err
		}
		tcpcn = tlscn
	}

	ldapcn := ldap.NewConn(tcpcn, c.IsTLS)

	ldapcn.Start()
	return &ldapConn{Conn: ldapcn, BaseDN: c.BaseDN, RoleBaseDN: c.RoleBaseDN}, nil
}

type ldapConn struct {
	*ldap.Conn
	BaseDN     string
	RoleBaseDN string
}

func (c *ldapConn) Bind(bindDN, password string) error {
	err := c.Conn.Bind(bindDN, password)
	if ldapErr, ok := err.(*ldap.Error); ok && ldapErr.ResultCode == ldap.LDAPResultInvalidCredentials {
		return errInvalidCredentials
	}
	return err
}

func (c *ldapConn) SearchUser(user string, attrs ...string) ([]map[string]interface{}, error) {
	query := fmt.Sprintf(
		"(&(|(objectClass=organizationalPerson)(objectClass=inetOrgPerson))"+
			"(|(uid=%[1]s)(mail=%[1]s)(userPrincipalName=%[1]s)(sAMAccountName=%[1]s)))", user)
	return c.searchEntries(c.BaseDN, query, attrs)
}

func (c *ldapConn) SearchUserRoles(user string, attrs ...string) ([]map[string]interface{}, error) {
	query := fmt.Sprintf("(|"+
		"(&(|(objectClass=group)(objectClass=groupOfNames))(member=%[1]s))"+
		"(&(objectClass=groupOfUniqueNames)(uniqueMember=%[1]s))"+
		")", user)
	return c.searchEntries(c.RoleBaseDN, query, attrs)
}

// searchEntries executes a LDAP query, and returns a result as entries where each entry is mapping of LDAP attributes.
func (c *ldapConn) searchEntries(baseDN, query string, attrs []string) ([]map[string]interface{}, error) {
	req := ldap.NewSearchRequest(baseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false, query, attrs, nil)
	res, err := c.Search(req)
	if err != nil {
		return nil, err
	}

	var entries []map[string]interface{}
	for _, v := range res.Entries {
		entry := map[string]interface{}{"dn": v.DN}
		for _, attr := range v.Attributes {
			// We need the first value only for the named attribute.
			entry[attr.Name] = attr.Values[0]
		}
		entries = append(entries, entry)
	}
	return entries, nil
}
