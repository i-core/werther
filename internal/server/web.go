/*
Copyright (C) JSC iCore - All Rights Reserved

Unauthorized copying of this file, via any medium is strictly prohibited
Proprietary and confidential

Written by Konstantin Lepa <klepa@i-core.ru>, December 2018
*/

//go:generate go run github.com/kevinburke/go-bindata/go-bindata -o templates.go -pkg server -prefix templates/ templates/...

package server

import (
	"fmt"
	"html/template"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
)

// intWebLoader is a loader that is used for serving embedded HTML/JS/CSS static files.
// They are embedded in a generated Go code.
type intWebLoader struct {
	tmpls map[string]*template.Template
}

// newIntWebLoader creates an internal web loader's instance.
func newIntWebLoader() (*intWebLoader, error) {
	mainTmpl, err := template.New("main").Parse(mainT)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse the main template")
	}

	tmpls := make(map[string]*template.Template)
	for _, name := range AssetNames() {
		t, err := mainTmpl.Clone()
		if err != nil {
			return nil, errors.Wrap(err, "failed to clone the main template")
		}
		asset, err := Asset(name)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to load asset %q", name)
		}
		tmpls[path.Base(name)] = template.Must(t.Parse(string(asset)))
	}
	return &intWebLoader{tmpls: tmpls}, nil
}

func (wl *intWebLoader) loadTemplate(name string) (*template.Template, error) {
	t, ok := wl.tmpls[name]
	if !ok {
		return nil, fmt.Errorf("the template %q does not exist", name)
	}
	return t, nil
}

// extWebLoader is a loader that is used for serving HTML/JS/CSS static files.
// The files must be provided at startup.
type extWebLoader struct {
	root  *template.Template
	paths map[string]string
}

// newExtWebLoader creates an external web loader's instance.
// The implementation affords to replace static files without restart of the app.
func newExtWebLoader(webDir string) (*extWebLoader, error) {
	if _, err := os.Stat(webDir); err != nil {
		return nil, errors.Wrapf(err, "failed to load web dir %q", webDir)
	}
	files, err := filepath.Glob(path.Join(webDir, "*.tmpl"))
	if err != nil {
		return nil, errors.Wrapf(err, "failed to load templates from web dir %q", webDir)
	}

	for i, f := range files {
		if !strings.HasSuffix(f, ".tmpl") {
			files = append(files[:i], files[i+1:]...)
		}
	}
	for i, f := range files {
		files[i] = path.Join("web", f)
	}

	mainTmpl, err := template.New("main").Parse(mainT)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse the main template")
	}

	paths := make(map[string]string)
	for _, f := range files {
		paths[path.Base(f)] = f
	}
	return &extWebLoader{root: mainTmpl, paths: paths}, nil
}

func (wl *extWebLoader) loadTemplate(name string) (*template.Template, error) {
	p, ok := wl.paths[name]
	if !ok {
		return nil, fmt.Errorf("the template %q does not exist", name)
	}
	t, err := wl.root.Clone()
	if err != nil {
		return nil, errors.Wrapf(err, "failed to clone the template %q", name)
	}
	return t.ParseFiles(p)
}

const mainT = `{{ define "main" }}
<!DOCTYPE html>
<html>
	<head>
		<meta name="viewport" content="width=device-width, initial-scale=1">
		<title>{{ block "title" . }}{{ end }}</title>
		<base href={{ .WebBasePath }}>
		{{ block "style". }}{{ end }}
	</head>
	<body>
		{{ block "content" . }}<h1>NO CONTENT</h1>{{ end }}
		{{ block "js" . }}{{ end }}
	</body>
</html>
{{ end }}
`
