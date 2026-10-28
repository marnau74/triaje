// Package riesgo calcula la gravedad CVSS y decide la prioridad de cada
// vulnerabilidad combinando gravedad, probabilidad de explotación (EPSS) y
// explotación confirmada (KEV).
package riesgo

import (
	"fmt"
	"math"
	"strings"
)

// PuntuacionCVSS3 calcula la puntuación base de un vector CVSS 3.0 o 3.1 según
// la especificación de FIRST (apartado 7.1 y apéndice A para el redondeo).
// OSV da el vector, no la puntuación, así que hay que calcularla.
func PuntuacionCVSS3(vector string) (float64, error) {
	partes := strings.Split(vector, "/")
	if len(partes) == 0 || !(partes[0] == "CVSS:3.0" || partes[0] == "CVSS:3.1") {
		return 0, fmt.Errorf("no es un vector CVSS 3: %q", vector)
	}
	m := map[string]string{}
	for _, p := range partes[1:] {
		k, v, ok := strings.Cut(p, ":")
		if !ok {
			return 0, fmt.Errorf("métrica mal formada %q", p)
		}
		m[k] = v
	}

	valor := func(metrica string, tabla map[string]float64) (float64, error) {
		v, ok := tabla[m[metrica]]
		if !ok {
			return 0, fmt.Errorf("falta o no es válida la métrica %s en %q", metrica, vector)
		}
		return v, nil
	}
	cambiaAlcance := m["S"] == "C"
	if m["S"] != "C" && m["S"] != "U" {
		return 0, fmt.Errorf("falta o no es válida la métrica S en %q", vector)
	}
	privilegios := map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}
	if cambiaAlcance {
		privilegios = map[string]float64{"N": 0.85, "L": 0.68, "H": 0.5}
	}
	impacto := map[string]float64{"H": 0.56, "L": 0.22, "N": 0}

	av, err := valor("AV", map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2})
	if err != nil {
		return 0, err
	}
	ac, err := valor("AC", map[string]float64{"L": 0.77, "H": 0.44})
	if err != nil {
		return 0, err
	}
	pr, err := valor("PR", privilegios)
	if err != nil {
		return 0, err
	}
	ui, err := valor("UI", map[string]float64{"N": 0.85, "R": 0.62})
	if err != nil {
		return 0, err
	}
	c, err := valor("C", impacto)
	if err != nil {
		return 0, err
	}
	i, err := valor("I", impacto)
	if err != nil {
		return 0, err
	}
	a, err := valor("A", impacto)
	if err != nil {
		return 0, err
	}

	iss := 1 - (1-c)*(1-i)*(1-a)
	var imp float64
	if cambiaAlcance {
		imp = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	} else {
		imp = 6.42 * iss
	}
	explotabilidad := 8.22 * av * ac * pr * ui
	if imp <= 0 {
		return 0, nil
	}
	if cambiaAlcance {
		return redondearArriba(math.Min(1.08*(imp+explotabilidad), 10)), nil
	}
	return redondearArriba(math.Min(imp+explotabilidad, 10)), nil
}

// redondearArriba es el Roundup de CVSS 3.1: el menor número con un decimal
// que sea mayor o igual que x, evitando los errores de coma flotante
// (sin este cuidado, 4.000000001 daría 4.1).
func redondearArriba(x float64) float64 {
	entero := int64(math.Round(x * 100000))
	if entero%10000 == 0 {
		return float64(entero) / 100000
	}
	return float64(entero/10000+1) / 10
}

// EtiquetaCVSS es la escala cualitativa de CVSS 3 (apartado 5).
func EtiquetaCVSS(p float64) string {
	switch {
	case p == 0:
		return "ninguna"
	case p < 4:
		return "baja"
	case p < 7:
		return "media"
	case p < 9:
		return "alta"
	default:
		return "crítica"
	}
}
