package inventario

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"net/url"
	"regexp"
	"strings"
)

// go.mod: las líneas require, sueltas o en bloque. Desde Go 1.17 el go.mod
// incluye también las dependencias indirectas, así que con él basta.
// Añade además la biblioteca estándar (paquete "stdlib"), que también tiene
// vulnerabilidades, con la versión de toolchain o la de la directiva go.
func leerGoMod(datos []byte, origen string) ([]Paquete, error) {
	var ps []Paquete
	var versionGo, toolchain string
	enBloque := false
	sc := bufio.NewScanner(bytes.NewReader(datos))
	for sc.Scan() {
		linea := sc.Text()
		if i := strings.Index(linea, "//"); i >= 0 {
			linea = linea[:i]
		}
		linea = strings.TrimSpace(linea)
		campos := strings.Fields(linea)
		switch {
		case len(campos) == 0:
			continue
		case enBloque && campos[0] == ")":
			enBloque = false
		case enBloque:
			if len(campos) >= 2 {
				ps = append(ps, paqueteGo(campos[0], campos[1], origen))
			}
		case campos[0] == "require" && len(campos) == 2 && campos[1] == "(":
			enBloque = true
		case campos[0] == "require" && len(campos) >= 3:
			ps = append(ps, paqueteGo(campos[1], campos[2], origen))
		case campos[0] == "go" && len(campos) == 2:
			versionGo = campos[1]
		case campos[0] == "toolchain" && len(campos) == 2:
			toolchain = strings.TrimPrefix(campos[1], "go")
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	v := toolchain
	if v == "" {
		v = versionGo
	}
	// "1.22" no dice qué parche se usa; solo "1.22.3" sirve para buscar.
	if strings.Count(v, ".") == 2 {
		ps = append(ps, Paquete{Ecosistema: Go, Nombre: "stdlib", Version: v, Origen: origen})
	}
	return ps, nil
}

func paqueteGo(modulo, version, origen string) Paquete {
	version = strings.TrimSuffix(strings.TrimPrefix(version, "v"), "+incompatible")
	return Paquete{Ecosistema: Go, Nombre: modulo, Version: version, Origen: origen}
}

// package-lock.json: formato 2 y 3 (clave "packages") y formato 1 (clave
// "dependencies", anidada).
func leerPackageLock(datos []byte, origen string) ([]Paquete, error) {
	var lock struct {
		Packages map[string]struct {
			Version string `json:"version"`
			Name    string `json:"name"`
			Link    bool   `json:"link"`
		} `json:"packages"`
		Dependencies map[string]depNPMv1 `json:"dependencies"`
	}
	if err := json.Unmarshal(datos, &lock); err != nil {
		return nil, err
	}
	var ps []Paquete
	if lock.Packages != nil {
		for ruta, p := range lock.Packages {
			if ruta == "" || p.Link {
				continue // el propio proyecto o un enlace a una carpeta local
			}
			nombre := p.Name
			if i := strings.LastIndex(ruta, "node_modules/"); i >= 0 {
				nombre = ruta[i+len("node_modules/"):]
			}
			if nombre == "" {
				continue
			}
			ps = append(ps, Paquete{Ecosistema: NPM, Nombre: nombre, Version: p.Version, Origen: origen})
		}
		return ps, nil
	}
	var recorrer func(map[string]depNPMv1)
	recorrer = func(deps map[string]depNPMv1) {
		for nombre, d := range deps {
			ps = append(ps, Paquete{Ecosistema: NPM, Nombre: nombre, Version: d.Version, Origen: origen})
			recorrer(d.Dependencies)
		}
	}
	recorrer(lock.Dependencies)
	return ps, nil
}

type depNPMv1 struct {
	Version      string              `json:"version"`
	Dependencies map[string]depNPMv1 `json:"dependencies"`
}

// requirements.txt: solo las versiones fijadas con "==". Un rango (">=") no
// dice qué versión se instala, así que no se puede comprobar.
var lineaRequirement = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*===?\s*([^\s;#]+)`)

func leerRequirements(datos []byte, origen string) ([]Paquete, error) {
	var ps []Paquete
	sc := bufio.NewScanner(bytes.NewReader(datos))
	for sc.Scan() {
		linea := strings.TrimSpace(sc.Text())
		if linea == "" || strings.HasPrefix(linea, "#") || strings.HasPrefix(linea, "-") {
			continue
		}
		m := lineaRequirement.FindStringSubmatch(linea)
		if m == nil {
			continue
		}
		ps = append(ps, Paquete{Ecosistema: PyPI, Nombre: normalizarPyPI(m[1]), Version: m[2], Origen: origen})
	}
	return ps, sc.Err()
}

// PEP 503: minúsculas y cualquier serie de "-", "_" o "." vale lo mismo.
var separadoresPyPI = regexp.MustCompile(`[-_.]+`)

func normalizarPyPI(nombre string) string {
	return separadoresPyPI.ReplaceAllString(strings.ToLower(nombre), "-")
}

// Cargo.lock: bloques [[package]] con name, version y source. No hace falta
// un lector de TOML completo para este formato tan regular. Los crates del
// propio workspace no tienen source (no vienen de crates.io) y se descartan.
func leerCargoLock(datos []byte, origen string) ([]Paquete, error) {
	var ps []Paquete
	var nombre, version, fuente string
	enPaquete := false
	cerrar := func() {
		if enPaquete && strings.HasPrefix(fuente, "registry+") {
			ps = append(ps, Paquete{Ecosistema: CratesIO, Nombre: nombre, Version: version, Origen: origen})
		}
		nombre, version, fuente, enPaquete = "", "", "", false
	}
	sc := bufio.NewScanner(bytes.NewReader(datos))
	for sc.Scan() {
		linea := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(linea, "[") {
			cerrar()
			enPaquete = linea == "[[package]]"
			continue
		}
		clave, valor, ok := strings.Cut(linea, "=")
		if !enPaquete || !ok {
			continue
		}
		valor = strings.Trim(strings.TrimSpace(valor), `"`)
		switch strings.TrimSpace(clave) {
		case "name":
			nombre = valor
		case "version":
			version = valor
		case "source":
			fuente = valor
		}
	}
	cerrar()
	return ps, sc.Err()
}

// packages.lock.json de NuGet: dependencias resueltas por cada framework.
func leerNuGetLock(datos []byte, origen string) ([]Paquete, error) {
	var lock struct {
		Dependencies map[string]map[string]struct {
			Type     string `json:"type"`
			Resolved string `json:"resolved"`
		} `json:"dependencies"`
	}
	if err := json.Unmarshal(datos, &lock); err != nil {
		return nil, err
	}
	var ps []Paquete
	for _, deps := range lock.Dependencies {
		for nombre, d := range deps {
			if d.Type == "Project" {
				continue
			}
			ps = append(ps, Paquete{Ecosistema: NuGet, Nombre: nombre, Version: d.Resolved, Origen: origen})
		}
	}
	return ps, nil
}

// SBOM CycloneDX en JSON: los componentes con purl, también los anidados.
func leerCycloneDX(datos []byte, origen string) ([]Paquete, error) {
	var bom struct {
		BOMFormat  string          `json:"bomFormat"`
		Components []componenteCDX `json:"components"`
	}
	if err := json.Unmarshal(datos, &bom); err != nil {
		return nil, err
	}
	if bom.BOMFormat != "CycloneDX" {
		return nil, errors.New("no es un SBOM CycloneDX (falta bomFormat)")
	}
	var ps []Paquete
	var recorrer func([]componenteCDX)
	recorrer = func(cs []componenteCDX) {
		for _, c := range cs {
			if p, ok := desdePURL(c.PURL); ok {
				p.Origen = origen
				ps = append(ps, p)
			}
			recorrer(c.Components)
		}
	}
	recorrer(bom.Components)
	return ps, nil
}

type componenteCDX struct {
	PURL       string          `json:"purl"`
	Components []componenteCDX `json:"components"`
}

var ecosistemaPorTipoPURL = map[string]Ecosistema{
	"golang": Go, "npm": NPM, "pypi": PyPI, "maven": Maven, "nuget": NuGet, "cargo": CratesIO,
}

// desdePURL interpreta un package URL: pkg:tipo/espacio/nombre@version?calificadores#subruta
func desdePURL(purl string) (Paquete, bool) {
	resto, ok := strings.CutPrefix(purl, "pkg:")
	if !ok {
		return Paquete{}, false
	}
	if i := strings.IndexAny(resto, "?#"); i >= 0 {
		resto = resto[:i]
	}
	tipo, ruta, ok := strings.Cut(resto, "/")
	if !ok {
		return Paquete{}, false
	}
	eco, ok := ecosistemaPorTipoPURL[strings.ToLower(tipo)]
	if !ok {
		return Paquete{}, false
	}
	i := strings.LastIndex(ruta, "@")
	if i < 0 {
		return Paquete{}, false
	}
	nombre, version := ruta[:i], ruta[i+1:]
	if n, err := url.PathUnescape(nombre); err == nil {
		nombre = n
	}
	if v, err := url.PathUnescape(version); err == nil {
		version = v
	}
	switch eco {
	case Maven:
		nombre = strings.Replace(nombre, "/", ":", 1) // grupo:artefacto
	case Go:
		version = strings.TrimSuffix(strings.TrimPrefix(version, "v"), "+incompatible")
	case PyPI:
		nombre = normalizarPyPI(nombre)
	}
	return Paquete{Ecosistema: eco, Nombre: nombre, Version: version}, true
}
