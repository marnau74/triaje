// Package inventario lee los ficheros de dependencias de un proyecto (o un SBOM)
// y devuelve la lista de paquetes con su versión exacta.
package inventario

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Ecosistema usa los nombres que espera OSV.
type Ecosistema string

const (
	Go       Ecosistema = "Go"
	NPM      Ecosistema = "npm"
	PyPI     Ecosistema = "PyPI"
	Maven    Ecosistema = "Maven"
	NuGet    Ecosistema = "NuGet"
	CratesIO Ecosistema = "crates.io"
)

// Paquete es una dependencia concreta encontrada en un fichero.
type Paquete struct {
	Ecosistema Ecosistema `json:"ecosistema"`
	Nombre     string     `json:"nombre"`
	Version    string     `json:"version"`
	Origen     string     `json:"origen"` // fichero en el que aparece
}

func (p Paquete) Clave() string {
	return string(p.Ecosistema) + "|" + p.Nombre + "|" + p.Version
}

type lector func(datos []byte, origen string) ([]Paquete, error)

// lectorPara decide qué lector usar según el nombre del fichero. Devuelve nil si
// el fichero no es de dependencias.
func lectorPara(nombre string) lector {
	base := strings.ToLower(filepath.Base(nombre))
	switch {
	case base == "go.mod":
		return leerGoMod
	case base == "package-lock.json" || base == "npm-shrinkwrap.json":
		return leerPackageLock
	case base == "requirements.txt" || (strings.HasPrefix(base, "requirements") && strings.HasSuffix(base, ".txt")):
		return leerRequirements
	case base == "cargo.lock":
		return leerCargoLock
	case base == "packages.lock.json":
		return leerNuGetLock
	case strings.HasSuffix(base, ".cdx.json") || base == "bom.json" || base == "sbom.json":
		return leerCycloneDX
	}
	return nil
}

// carpetas que no se recorren: dependencias descargadas, no declaradas.
var carpetasIgnoradas = map[string]bool{
	".git": true, "node_modules": true, "vendor": true, ".venv": true, "venv": true,
	"target": true, "bin": true, "obj": true, "dist": true, "build": true,
}

// Leer acepta un fichero o una carpeta. En una carpeta busca de forma recursiva
// todos los ficheros que sabe leer.
func Leer(ruta string) ([]Paquete, error) {
	info, err := os.Stat(ruta)
	if err != nil {
		return nil, err
	}
	var ficheros []string
	if info.IsDir() {
		err = filepath.WalkDir(ruta, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if p != ruta && carpetasIgnoradas[d.Name()] {
					return filepath.SkipDir
				}
				return nil
			}
			if lectorPara(p) != nil {
				ficheros = append(ficheros, p)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	} else {
		if lectorPara(ruta) == nil {
			return nil, fmt.Errorf("no sé leer %q: formatos admitidos go.mod, package-lock.json, requirements*.txt, Cargo.lock, packages.lock.json y SBOM CycloneDX (*.cdx.json, bom.json)", ruta)
		}
		ficheros = []string{ruta}
	}
	if len(ficheros) == 0 {
		return nil, errors.New("no he encontrado ningún fichero de dependencias")
	}

	var todos []Paquete
	for _, f := range ficheros {
		datos, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		origen := f
		if info.IsDir() {
			if rel, err := filepath.Rel(ruta, f); err == nil {
				origen = rel
			}
		}
		origen = filepath.ToSlash(origen)
		paquetes, err := lectorPara(f)(datos, origen)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", origen, err)
		}
		todos = append(todos, paquetes...)
	}
	return sinDuplicados(todos), nil
}

// sinDuplicados quita los paquetes repetidos dentro del mismo fichero y los
// deja en un orden estable.
func sinDuplicados(ps []Paquete) []Paquete {
	vistos := map[string]bool{}
	var res []Paquete
	for _, p := range ps {
		if p.Nombre == "" || p.Version == "" {
			continue
		}
		k := p.Origen + "|" + p.Clave()
		if vistos[k] {
			continue
		}
		vistos[k] = true
		res = append(res, p)
	}
	sort.SliceStable(res, func(i, j int) bool {
		if res[i].Origen != res[j].Origen {
			return res[i].Origen < res[j].Origen
		}
		return res[i].Nombre < res[j].Nombre
	})
	return res
}
