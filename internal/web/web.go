/*
Copyright (c) JSC iCore.

This source code is licensed under the MIT license found in the
LICENSE file in the root directory of this source tree.
*/

//go:generate go run github.com/kevinburke/go-bindata/go-bindata -o templates.go -pkg web -prefix templates/ templates/...

package web

import (
	"bufio"
	"bytes"
	"fmt"
	"html/template"
	"io/ioutil"
	"net/http"
	"os"
	"path"

	assetfs "github.com/elazarl/go-bindata-assetfs"
	"github.com/i-core/routegroup"
	"github.com/pkg/errors"
	"golang.org/x/text/language"
)

// The file systems provide templates and their resources that are stored in the application's internal assets.
// The variables are needed to be able to override them in tests.
var (
	intTmplsFS  http.FileSystem = &assetfs.AssetFS{Asset: Asset, AssetDir: AssetDir, AssetInfo: AssetInfo}
	intStaticFS http.FileSystem = &assetfs.AssetFS{Asset: Asset, AssetDir: AssetDir, AssetInfo: AssetInfo, Prefix: "static"}
)

// Config is a configuration of a template's renderer and HTTP handler for static files.
type Config struct {
	Dir      string `envconfig:"dir" desc:"a path to an external web directory"`
	BasePath string `envconfig:"base_path" default:"/" desc:"a base path of web pages"`
}

// HTMLRenderer renders a HTML page from a Go template.
//
// A template's source for a HTML page should contain four blocks:
// "title", "style", "js", "content". Block "title" should contain the content of the "title" HTML tag.
// Block "style" should contain "link" HTML tags that are injected to the head of the page.
// Block "js" should contain "script" HTML tags that are injected to the bottom of the page's body.
// Block "content" should contain HTML content that is injected to the start of the page's body.
// Each block has access to data that is specified using the method "RenderTemplate" of HTMLRenderer.
//
// By default, HTMLRenderer loads a template's source from the application's internal assets.
// The application's internal assets include the login page's template only (template with name "login.tmpl").
//
// Besides it, HTMLRenderer can load templates' sources from an external directory.
// The external directory is specified via a config.
//
// Templates can contain links to resources (styles and scripts). In that case, the template's directory has to
// contain directory "static" with these resources. To provide these resources to a user you should register
// StaticHandler in the application's HTTP router with path "/static".
type HTMLRenderer struct {
	Config
	mainTmpl *template.Template
	fs       http.FileSystem
}

// NewHTMLRenderer returns a new instance of HTMLRenderer.
func NewHTMLRenderer(cnf Config) (*HTMLRenderer, error) {
	mainTmpl, err := template.New("main").Parse(mainT)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create template's renderer")
	}
	fs := intTmplsFS
	if cnf.Dir != "" {
		fs = http.Dir(cnf.Dir)
	}
	return &HTMLRenderer{Config: cnf, mainTmpl: mainTmpl, fs: fs}, nil
}

type langPref struct {
	Lang   string
	Weight float32
}

// RenderTemplate renders a HTML page from a template with the specified name using the specified data.
func (r *HTMLRenderer) RenderTemplate(w http.ResponseWriter, req *http.Request, name string, data interface{}) error {
	// Read and parse the requested template.
	f, err := r.fs.Open(name)
	if err != nil {
		if v, ok := err.(*os.PathError); ok {
			if os.IsNotExist(v.Err) {
				return fmt.Errorf("the template %q does not exist", name)
			}
		}
		return fmt.Errorf("failed to open template %q: %s", name, err)
	}
	b, err := ioutil.ReadAll(f)
	if err != nil {
		return fmt.Errorf("failed to read template %q: %s", name, err)
	}
	root, err := template.New("main").Parse(string(b))
	if err != nil {
		return errors.Wrapf(err, "failed to parse template %q: %s", name, err)
	}

	// The old-style template of a web page showed itself as not flexible.
	// It was changed with a new template that allows overriding the whole page.
	// The old-style template left for backward compatibility
	// and will be deprecated in the future major release.
	if isOldStyleUserTemplate(root) {
		var wrapper *template.Template
		wrapper, err = r.mainTmpl.Clone()
		if err != nil {
			return errors.Wrapf(err, "failed to clone the main template for template %q: %s", name, err)
		}
		root, err = root.AddParseTree("main", wrapper.Tree)
		if err != nil {
			return errors.Wrapf(err, "failed to create the main template for template %q: %s", name, err)
		}
	}

	// Prepare template data.
	basePath := r.BasePath
	if basePath == "" {
		basePath = "/"
	}

	var langPrefs []langPref
	if acceptLang := req.Header.Get("Accept-Language"); acceptLang != "" {
		var tags []language.Tag
		var weights []float32
		tags, weights, err = language.ParseAcceptLanguage(acceptLang)
		if err != nil {
			return errors.Wrapf(err, "failed to parse the header \"Accept-Language\": %s", err)
		}
		for i, tag := range tags {
			langPrefs = append(langPrefs, langPref{Lang: tag.String(), Weight: weights[i]})
		}
	} else {
		langPrefs = []langPref{{Lang: "en", Weight: 1}}
	}

	tmplData := map[string]interface{}{"WebBasePath": basePath, "LangPrefs": langPrefs, "Data": data}

	// Render the template.
	var (
		buf bytes.Buffer
		bw  = bufio.NewWriter(&buf)
	)
	if err = root.Execute(bw, tmplData); err != nil {
		return err
	}
	if err = bw.Flush(); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, err = buf.WriteTo(w)
	return err
}

// Returns true if a template is the old-style template.
//
// A template is considered as the old-style template
// if it contains four blocks for customizing the page title,
// styles, markup, and scripts.
//
// See https://github.com/i-core/werther/issues/11.
func isOldStyleUserTemplate(root *template.Template) bool {
	var tmpls []string
	for _, tmpl := range root.Templates() {
		tmpls = append(tmpls, tmpl.Name())
	}
	contains := func(arr []string, tgt string) bool {
		for _, item := range arr {
			if item == tgt {
				return true
			}
		}
		return false
	}
	return contains(tmpls, "title") && contains(tmpls, "style") && contains(tmpls, "js") && contains(tmpls, "content")
}

var mainT = `{{ define "main" }}
<!DOCTYPE html>
<html lang="{{ (index .LangPrefs 0).Lang }}">
	<head>
		<meta name="viewport" content="width=device-width, initial-scale=1">
		<title>{{ block "title" .Data }}{{ end }}</title>
		<base href="{{ .WebBasePath }}">
		{{ block "style" .Data }}{{ end }}
	</head>
	<body>
		{{ block "content" .Data }}<h1>NO CONTENT</h1>{{ end }}
		{{ block "js" .Data }}{{ end }}
	</body>
</html>
{{ end }}
`

// StaticHandler provides HTTP handler that serves static files.
type StaticHandler struct {
	fs http.FileSystem
}

// NewStaticHandler creates a new instance of StaticHandler.
func NewStaticHandler(cnf Config) *StaticHandler {
	fs := intStaticFS
	if cnf.Dir != "" {
		fs = http.Dir(path.Join(cnf.Dir, "static"))
	}
	return &StaticHandler{fs: fs}
}

// AddRoutes registers a route that serves static files.
func (h *StaticHandler) AddRoutes(apply func(m, p string, h http.Handler, mws ...func(http.Handler) http.Handler)) {
	fileServer := http.FileServer(h.fs)
	apply(http.MethodGet, "/*filepath", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.URL.Path = routegroup.PathParam(r.Context(), "filepath")
		fileServer.ServeHTTP(w, r)
	}))
}
