package analisis

import (
	"sort"
	"strings"
	"unicode"

	"github.com/marnau74/triaje/internal/fuentes"
	"github.com/marnau74/triaje/internal/inventario"
	"github.com/marnau74/triaje/internal/riesgo"
)

// agruparAlias quita los duplicados: OSV junta varias bases de datos y una
// misma vulnerabilidad puede llegar como GHSA-..., PYSEC-... y GO-... a la
// vez, enlazadas por sus alias. Se queda una por grupo, la que tenga vector
// CVSS 3 si alguna lo tiene, y le suma los alias de las demás.
func agruparAlias(ids []string, vulns map[string]*fuentes.Vulnerabilidad) []*fuentes.Vulnerabilidad {
	var lista []*fuentes.Vulnerabilidad
	for _, id := range ids {
		if v, ok := vulns[id]; ok {
			lista = append(lista, v)
		}
	}
	sort.SliceStable(lista, func(i, j int) bool {
		ti, tj := tieneCVSS3(lista[i]), tieneCVSS3(lista[j])
		if ti != tj {
			return ti
		}
		return lista[i].ID < lista[j].ID
	})

	grupoDe := map[string]*fuentes.Vulnerabilidad{} // id o alias -> representante
	var res []*fuentes.Vulnerabilidad
	for _, v := range lista {
		nombres := append([]string{v.ID}, v.Aliases...)
		var rep *fuentes.Vulnerabilidad
		for _, n := range nombres {
			if r, ok := grupoDe[n]; ok {
				rep = r
				break
			}
		}
		if rep == nil {
			copia := *v
			copia.Aliases = append([]string(nil), v.Aliases...)
			rep = &copia
			res = append(res, rep)
		} else {
			rep.Aliases = append(rep.Aliases, nombres...)
		}
		for _, n := range nombres {
			grupoDe[n] = rep
		}
	}
	return res
}

func tieneCVSS3(v *fuentes.Vulnerabilidad) bool {
	for _, s := range v.Severity {
		if s.Type == "CVSS_V3" {
			return true
		}
	}
	return false
}

// gravedad devuelve la puntuación CVSS 3 calculada desde el vector. Si no
// hay vector 3 pero la base de datos da una etiqueta (GitHub pone HIGH,
// CRITICAL...), usa un valor representativo y lo marca como aproximado.
func gravedad(v *fuentes.Vulnerabilidad) (puntos float64, vector string, aproximado bool) {
	for _, s := range v.Severity {
		if s.Type != "CVSS_V3" {
			continue
		}
		if p, err := riesgo.PuntuacionCVSS3(s.Score); err == nil {
			return p, s.Score, false
		}
	}
	etiqueta, _ := v.DatabaseSpecific["severity"].(string)
	switch strings.ToUpper(etiqueta) {
	case "CRITICAL":
		return 9.0, "", true
	case "HIGH":
		return 7.5, "", true
	case "MODERATE", "MEDIUM":
		return 5.0, "", true
	case "LOW":
		return 2.0, "", true
	}
	return 0, "", false
}

// versionArreglada busca, entre los rangos del paquete afectado, la primera
// versión corregida posterior a la instalada.
func versionArreglada(v *fuentes.Vulnerabilidad, p inventario.Paquete) string {
	mejor := ""
	for _, a := range v.Affected {
		if a.Package.Ecosystem != string(p.Ecosistema) || !mismoNombre(a.Package.Name, p) {
			continue
		}
		for _, r := range a.Ranges {
			if r.Type == "GIT" {
				continue
			}
			for _, e := range r.Events {
				f, ok := e["fixed"]
				if !ok || compararVersiones(f, p.Version) <= 0 {
					continue
				}
				if mejor == "" || compararVersiones(f, mejor) < 0 {
					mejor = f
				}
			}
		}
	}
	return mejor
}

func mismoNombre(nombre string, p inventario.Paquete) bool {
	if p.Ecosistema == inventario.PyPI || p.Ecosistema == inventario.NuGet {
		return strings.EqualFold(strings.ReplaceAll(nombre, "_", "-"), strings.ReplaceAll(p.Nombre, "_", "-"))
	}
	return nombre == p.Nombre
}

// compararVersiones es una comparación tolerante que sirve para semver, PEP
// 440 y las versiones de NuGet y Maven más habituales: compara por trozos,
// los números como números, y una versión con sufijo de prelanzamiento
// (1.2.0-rc1, 1.2.0b1) va antes que la versión limpia (1.2.0).
func compararVersiones(a, b string) int {
	ta, tb := trozos(a), trozos(b)
	for i := 0; i < len(ta) || i < len(tb); i++ {
		switch {
		case i >= len(ta):
			return siguePrelanzamiento(tb[i:])
		case i >= len(tb):
			return -siguePrelanzamiento(ta[i:])
		}
		x, y := ta[i], tb[i]
		nx, ex := numero(x)
		ny, ey := numero(y)
		switch {
		case ex && ey:
			if nx != ny {
				return cmp(nx, ny)
			}
		case ex: // número frente a texto: el texto es un prelanzamiento
			return 1
		case ey:
			return -1
		default:
			if x != y {
				return strings.Compare(x, y)
			}
		}
	}
	return 0
}

// siguePrelanzamiento: si lo que le sobra a la versión más larga empieza por
// texto (rc, beta...), la larga es anterior; si son números (1.2 frente a
// 1.2.1), es posterior. Ceros sobrantes (1.2 frente a 1.2.0) son iguales.
func siguePrelanzamiento(resto []string) int {
	for _, t := range resto {
		if n, ok := numero(t); ok {
			if n != 0 {
				return -1
			}
			continue
		}
		return 1
	}
	return 0
}

func trozos(v string) []string {
	v = strings.TrimPrefix(strings.ToLower(v), "v")
	if i := strings.Index(v, "+"); i >= 0 {
		v = v[:i] // los metadatos de compilación no cuentan
	}
	var res []string
	var actual []rune
	esNumero := false
	for _, r := range v {
		d := unicode.IsDigit(r)
		separador := !d && !unicode.IsLetter(r)
		if separador || (len(actual) > 0 && d != esNumero) {
			if len(actual) > 0 {
				res = append(res, string(actual))
			}
			actual = nil
		}
		if !separador {
			actual = append(actual, r)
			esNumero = d
		}
	}
	if len(actual) > 0 {
		res = append(res, string(actual))
	}
	return res
}

func numero(s string) (int64, bool) {
	var n int64
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, false
		}
		n = n*10 + int64(r-'0')
	}
	return n, s != ""
}

func cmp(a, b int64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}
