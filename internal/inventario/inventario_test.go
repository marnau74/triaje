package inventario

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func nombresVersiones(ps []Paquete) map[string]string {
	m := map[string]string{}
	for _, p := range ps {
		m[p.Nombre] = p.Version
	}
	return m
}

func comprobar(t *testing.T, ps []Paquete, err error, quiero map[string]string) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	if got := nombresVersiones(ps); !reflect.DeepEqual(got, quiero) {
		t.Errorf("paquetes:\n got   %v\n quiero %v", got, quiero)
	}
}

func TestGoMod(t *testing.T) {
	ps, err := leerGoMod([]byte(`module ejemplo.local/x // comentario

go 1.22

toolchain go1.22.4

require github.com/suelto/uno v1.0.0

require (
	golang.org/x/net v0.7.0
	github.com/viejo/dos v2.0.0+incompatible // indirect

)

replace github.com/suelto/uno => ../uno
`), "go.mod")
	comprobar(t, ps, err, map[string]string{
		"github.com/suelto/uno": "1.0.0",
		"golang.org/x/net":      "0.7.0",
		"github.com/viejo/dos":  "2.0.0",
		"stdlib":                "1.22.4", // la de toolchain manda sobre la de go
	})
}

func TestGoModSinParche(t *testing.T) {
	// "go 1.22" no dice qué versión exacta se usa: no se añade stdlib.
	ps, err := leerGoMod([]byte("module x\n\ngo 1.22\n"), "go.mod")
	comprobar(t, ps, err, map[string]string{})
}

func TestPackageLockV3(t *testing.T) {
	ps, err := leerPackageLock([]byte(`{
  "lockfileVersion": 3,
  "packages": {
    "": {"name": "raiz", "version": "1.0.0"},
    "node_modules/lodash": {"version": "4.17.4"},
    "node_modules/@scope/pkg": {"version": "2.0.0"},
    "node_modules/express/node_modules/qs": {"version": "6.7.0"},
    "packages/local": {"version": "0.0.1", "name": "local"},
    "node_modules/local": {"link": true, "resolved": "packages/local"}
  }
}`), "package-lock.json")
	comprobar(t, ps, err, map[string]string{
		"lodash": "4.17.4", "@scope/pkg": "2.0.0", "qs": "6.7.0", "local": "0.0.1",
	})
}

func TestPackageLockV1(t *testing.T) {
	ps, err := leerPackageLock([]byte(`{
  "lockfileVersion": 1,
  "dependencies": {
    "express": {"version": "4.17.1", "dependencies": {"qs": {"version": "6.7.0"}}},
    "minimist": {"version": "1.2.0"}
  }
}`), "package-lock.json")
	comprobar(t, ps, err, map[string]string{"express": "4.17.1", "qs": "6.7.0", "minimist": "1.2.0"})
}

func TestRequirements(t *testing.T) {
	ps, err := leerRequirements([]byte(`# comentario
-r base.txt
--index-url https://ejemplo
Django==3.2.0
requests[security] == 2.25.1 ; python_version >= "3.8"
Zope.Interface===5.0
Jinja2>=3.0
pkg_con_guion==1.0  # fijada
`), "requirements.txt")
	comprobar(t, ps, err, map[string]string{
		"django": "3.2.0", "requests": "2.25.1", "zope-interface": "5.0", "pkg-con-guion": "1.0",
	})
}

func TestCargoLock(t *testing.T) {
	ps, err := leerCargoLock([]byte(`version = 3

[[package]]
name = "mi-crate"
version = "0.1.0"
dependencies = ["serde"]

[[package]]
name = "serde"
version = "1.0.100"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "abc"

[[package]]
name = "de-git"
version = "0.3.0"
source = "git+https://github.com/x/y#abc"

[metadata]
name = "no-es-un-paquete"
`), "Cargo.lock")
	comprobar(t, ps, err, map[string]string{"serde": "1.0.100"})
}

func TestNuGetLock(t *testing.T) {
	ps, err := leerNuGetLock([]byte(`{
  "version": 1,
  "dependencies": {
    "net8.0": {
      "Newtonsoft.Json": {"type": "Direct", "requested": "[12.0.1, )", "resolved": "12.0.1"},
      "System.Text.Json": {"type": "Transitive", "resolved": "8.0.0"},
      "MiProyecto.Core": {"type": "Project"}
    }
  }
}`), "packages.lock.json")
	comprobar(t, ps, err, map[string]string{"Newtonsoft.Json": "12.0.1", "System.Text.Json": "8.0.0"})
}

func TestCycloneDX(t *testing.T) {
	ps, err := leerCycloneDX([]byte(`{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "components": [
    {"name": "lodash", "purl": "pkg:npm/lodash@4.17.4"},
    {"name": "pkg", "purl": "pkg:npm/%40scope/pkg@2.0.0"},
    {"name": "log4j", "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1?type=jar",
      "components": [{"purl": "pkg:pypi/PyYAML@5.3.1"}]},
    {"name": "net", "purl": "pkg:golang/golang.org/x/net@v0.7.0"},
    {"name": "desconocido", "purl": "pkg:deb/debian/openssl@1.1.1"},
    {"name": "sin purl"}
  ]
}`), "bom.json")
	comprobar(t, ps, err, map[string]string{
		"lodash": "4.17.4", "@scope/pkg": "2.0.0",
		"org.apache.logging.log4j:log4j-core": "2.14.1",
		"pyyaml":                              "5.3.1",
		"golang.org/x/net":                    "0.7.0",
	})
	if _, err := leerCycloneDX([]byte(`{"spdxVersion": "SPDX-2.3"}`), "bom.json"); err == nil {
		t.Error("un SBOM que no es CycloneDX debería dar error")
	}
}

func TestLeerCarpeta(t *testing.T) {
	dir := t.TempDir()
	escribir := func(ruta, contenido string) {
		t.Helper()
		ruta = filepath.Join(dir, ruta)
		if err := os.MkdirAll(filepath.Dir(ruta), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(ruta, []byte(contenido), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	escribir("api/requirements.txt", "flask==1.0\n")
	escribir("web/package-lock.json", `{"packages": {"node_modules/lodash": {"version": "4.17.4"}}}`)
	// Lo que hay dentro de node_modules son dependencias descargadas: no se mira.
	escribir("web/node_modules/otro/package-lock.json", `{"packages": {"node_modules/x": {"version": "1.0.0"}}}`)
	escribir("README.md", "nada")

	ps, err := Leer(dir)
	if err != nil {
		t.Fatal(err)
	}
	quiero := []Paquete{
		{Ecosistema: PyPI, Nombre: "flask", Version: "1.0", Origen: "api/requirements.txt"},
		{Ecosistema: NPM, Nombre: "lodash", Version: "4.17.4", Origen: "web/package-lock.json"},
	}
	if !reflect.DeepEqual(ps, quiero) {
		t.Errorf("got %+v\nquiero %+v", ps, quiero)
	}

	if _, err := Leer(filepath.Join(dir, "README.md")); err == nil {
		t.Error("un fichero que no es de dependencias debería dar error")
	}
	if _, err := Leer(t.TempDir()); err == nil {
		t.Error("una carpeta sin ficheros de dependencias debería dar error")
	}
}
