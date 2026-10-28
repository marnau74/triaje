package riesgo

import (
	"fmt"
	"strings"
)

// Prioridad ordena qué arreglar primero. P1 es lo más urgente.
type Prioridad int

const (
	P1 Prioridad = iota + 1 // se está explotando
	P2                      // es probable que se explote pronto
	P3                      // grave o con alguna probabilidad de explotación
	P4                      // puede esperar a la próxima actualización rutinaria
)

func (p Prioridad) String() string { return fmt.Sprintf("P%d", int(p)) }

func (p Prioridad) Nombre() string {
	switch p {
	case P1:
		return "urgente"
	case P2:
		return "alta"
	case P3:
		return "media"
	default:
		return "baja"
	}
}

// ParsePrioridad acepta "p1".."p4" (sin distinguir mayúsculas).
func ParsePrioridad(s string) (Prioridad, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "p1":
		return P1, nil
	case "p2":
		return P2, nil
	case "p3":
		return P3, nil
	case "p4":
		return P4, nil
	}
	return 0, fmt.Errorf("prioridad desconocida %q (usa p1, p2, p3 o p4)", s)
}

// Umbrales de EPSS. FIRST recomienda mirar la probabilidad y no solo el
// percentil: un 10 % en 30 días ya está en el 1-2 % de CVE más peligrosas, y
// por debajo del 1 % la inmensa mayoría nunca llega a explotarse.
const (
	EPSSAlto  = 0.10
	EPSSMedio = 0.01
)

// Senales es lo que se sabe de una vulnerabilidad para decidir su prioridad.
type Senales struct {
	CVSS         float64
	CVSSConocido bool
	EPSS         float64
	EPSSConocido bool
	EnKEV        bool
	Ransomware   bool
}

// Decidir aplica las reglas en orden y devuelve la prioridad con el motivo
// explicado, para que nadie tenga que fiarse de un número sin saber de dónde
// sale. Las reglas, de más a menos urgente:
//
//	P1  está en el catálogo KEV: alguien la está explotando ya.
//	P2  EPSS ≥ 10 %, o crítica (CVSS ≥ 9) con EPSS ≥ 1 % o sin dato de EPSS.
//	P3  CVSS ≥ 7, EPSS ≥ 1 %, o no se sabe nada de ella (mejor revisarla).
//	P4  el resto: gravedad baja o media y explotación poco probable.
//
// Sin dato de EPSS (vulnerabilidades sin CVE) se decide solo por CVSS, del
// lado prudente.
func Decidir(s Senales) (Prioridad, string) {
	cvss := fmt.Sprintf("CVSS %s", decimal(s.CVSS, 1))
	epss := "EPSS " + Porcentaje(s.EPSS)

	switch {
	case s.EnKEV && s.Ransomware:
		return P1, "se está explotando (catálogo KEV de CISA) y se ha usado en campañas de ransomware"
	case s.EnKEV:
		return P1, "se está explotando (catálogo KEV de CISA)"
	case s.EPSSConocido && s.EPSS >= EPSSAlto:
		return P2, epss + ": probabilidad alta de que se explote en los próximos 30 días"
	case s.CVSSConocido && s.CVSS >= 9 && s.EPSSConocido && s.EPSS >= EPSSMedio:
		return P2, "crítica (" + cvss + ") y con probabilidad de explotación apreciable (" + epss + ")"
	case s.CVSSConocido && s.CVSS >= 9 && !s.EPSSConocido:
		return P2, "crítica (" + cvss + ") y sin dato de EPSS con el que descartarla"
	case s.CVSSConocido && s.CVSS >= 7:
		if s.EPSSConocido {
			return P3, "grave (" + cvss + ") pero con poca probabilidad de explotación (" + epss + ")"
		}
		return P3, "grave (" + cvss + "), sin dato de EPSS"
	case s.EPSSConocido && s.EPSS >= EPSSMedio:
		return P3, "probabilidad de explotación apreciable (" + epss + ")"
	case !s.CVSSConocido && !s.EPSSConocido:
		return P3, "sin datos de gravedad ni de explotación: conviene revisarla a mano"
	case !s.EPSSConocido:
		return P4, "gravedad " + EtiquetaCVSS(s.CVSS) + " (" + cvss + "), sin dato de EPSS"
	case !s.CVSSConocido:
		return P4, "explotación poco probable (" + epss + "), sin dato de gravedad"
	default:
		return P4, "gravedad " + EtiquetaCVSS(s.CVSS) + " (" + cvss + ") y explotación poco probable (" + epss + ")"
	}
}

// Porcentaje escribe una probabilidad EPSS con un decimal; por debajo de una
// décima dice «<0,1 %» en vez de un «0,0 %» que parece un cero, y cerca del
// máximo «>99,9 %» en vez de un «100,0 %» que parece una certeza.
func Porcentaje(p float64) string {
	switch {
	case p < 0.001:
		return "<0,1 %"
	case p > 0.999:
		return ">99,9 %"
	}
	return decimal(p*100, 1) + " %"
}

// decimal escribe el número con coma decimal, como se escribe en español.
func decimal(x float64, decimales int) string {
	return strings.Replace(fmt.Sprintf("%.*f", decimales, x), ".", ",", 1)
}

// En JSON se escribe como "P1", "P2"... y no como un número sin contexto.
func (p Prioridad) MarshalText() ([]byte, error) { return []byte(p.String()), nil }

func (p *Prioridad) UnmarshalText(b []byte) error {
	v, err := ParsePrioridad(string(b))
	*p = v
	return err
}
