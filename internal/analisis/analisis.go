// Package analisis junta las tres fuentes y produce el informe: una lista de
// hallazgos (paquete + vulnerabilidad) ordenada por prioridad.
package analisis

import (
	"context"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/marnau74/triaje/internal/fuentes"
	"github.com/marnau74/triaje/internal/inventario"
	"github.com/marnau74/triaje/internal/riesgo"
)

type Hallazgo struct {
	Paquete        inventario.Paquete  `json:"paquete"`
	ID             string              `json:"id"`
	CVEs           []string            `json:"cves,omitempty"`
	Resumen        string              `json:"resumen"`
	CVSS           float64             `json:"cvss,omitempty"`
	VectorCVSS     string              `json:"vector_cvss,omitempty"`
	CVSSAproximado bool                `json:"cvss_aproximado,omitempty"` // solo había la etiqueta (HIGH, CRITICAL...)
	EPSS           *fuentes.EPSS       `json:"epss,omitempty"`
	KEV            *fuentes.EntradaKEV `json:"kev,omitempty"`
	Prioridad      riesgo.Prioridad    `json:"prioridad"`
	Motivo         string              `json:"motivo"`
	Arreglo        string              `json:"version_arreglada,omitempty"`
	Enlace         string              `json:"enlace"`
}

type Informe struct {
	Generado  time.Time         `json:"generado"`
	Ruta      string            `json:"ruta"`
	Ficheros  []string          `json:"ficheros"`
	Paquetes  int               `json:"paquetes"`
	Hallazgos []Hallazgo        `json:"hallazgos"`
	Ocultos   int               `json:"ocultos,omitempty"` // quitados por Filtrar
	Plan      []Actualizacion   `json:"plan"`
	Resumen   map[string]int    `json:"resumen"` // hallazgos por prioridad
	Fuentes   map[string]string `json:"fuentes"`
	Avisos    []string          `json:"avisos,omitempty"`
}

// Analizar consulta las fuentes para los paquetes dados. Si EPSS o KEV fallan
// el análisis sigue (con un aviso) porque OSV es lo imprescindible; si falla
// OSV, devuelve el error.
func Analizar(ctx context.Context, c *fuentes.Cliente, ruta string, ps []inventario.Paquete) (*Informe, error) {
	inf := &Informe{
		Generado: time.Now().UTC().Truncate(time.Second),
		Ruta:     ruta,
		Paquetes: len(ps),
		Resumen:  map[string]int{"P1": 0, "P2": 0, "P3": 0, "P4": 0},
		Fuentes:  map[string]string{},
	}
	ficheros := map[string]bool{}
	for _, p := range ps {
		if !ficheros[p.Origen] {
			ficheros[p.Origen] = true
			inf.Ficheros = append(inf.Ficheros, p.Origen)
		}
	}

	idsPorPaquete, vulns, err := c.BuscarVulnerabilidades(ctx, ps)
	if err != nil {
		return nil, err
	}
	inf.Fuentes["osv"] = "api.osv.dev"

	// Hallazgos sin puntuar todavía, y las CVE que hay que preguntar a EPSS.
	var hallazgos []Hallazgo
	cves := map[string]bool{}
	for _, p := range ps {
		for _, v := range agruparAlias(idsPorPaquete[p.Clave()], vulns) {
			h := nuevoHallazgo(p, v)
			for _, cve := range h.CVEs {
				cves[cve] = true
			}
			hallazgos = append(hallazgos, h)
		}
	}

	var epss map[string]fuentes.EPSS
	if len(cves) > 0 {
		lista := make([]string, 0, len(cves))
		for cve := range cves {
			lista = append(lista, cve)
		}
		sort.Strings(lista)
		epss, err = c.BuscarEPSS(ctx, lista)
		if err != nil {
			inf.Avisos = append(inf.Avisos, "no se ha podido consultar EPSS ("+err.Error()+"): la prioridad se basa solo en CVSS y KEV")
		}
		for _, e := range epss {
			inf.Fuentes["epss"] = "FIRST EPSS, datos del " + e.Fecha
			break
		}
	}
	kev, err := c.CatalogoKEV(ctx)
	if err != nil {
		inf.Avisos = append(inf.Avisos, "no se ha podido descargar el catálogo KEV ("+err.Error()+"): no se marcará ninguna como explotada")
	} else {
		inf.Fuentes["kev"] = "CISA KEV, " + strconv.Itoa(len(kev)) + " vulnerabilidades"
	}

	for i := range hallazgos {
		puntuar(&hallazgos[i], epss, kev)
		inf.Resumen[hallazgos[i].Prioridad.String()]++
	}
	ordenar(hallazgos)
	inf.Hallazgos = hallazgos
	inf.Plan = planActualizacion(hallazgos)
	return inf, nil
}

func nuevoHallazgo(p inventario.Paquete, v *fuentes.Vulnerabilidad) Hallazgo {
	h := Hallazgo{
		Paquete: p,
		ID:      v.ID,
		CVEs:    cvesDe(v),
		Resumen: resumen(v),
		Arreglo: versionArreglada(v, p),
		Enlace:  "https://osv.dev/vulnerability/" + v.ID,
	}
	h.CVSS, h.VectorCVSS, h.CVSSAproximado = gravedad(v)
	return h
}

// puntuar añade EPSS y KEV y decide la prioridad. Si la vulnerabilidad tiene
// varias CVE se queda con la señal más alta de cada fuente.
func puntuar(h *Hallazgo, epss map[string]fuentes.EPSS, kev map[string]fuentes.EntradaKEV) {
	for _, cve := range h.CVEs {
		if e, ok := epss[cve]; ok && (h.EPSS == nil || e.Probabilidad > h.EPSS.Probabilidad) {
			e := e
			h.EPSS = &e
		}
		if k, ok := kev[cve]; ok && h.KEV == nil {
			k := k
			h.KEV = &k
		}
	}
	s := riesgo.Senales{CVSS: h.CVSS, CVSSConocido: h.CVSS > 0, EnKEV: h.KEV != nil}
	if h.EPSS != nil {
		s.EPSS, s.EPSSConocido = h.EPSS.Probabilidad, true
	}
	if h.KEV != nil {
		s.Ransomware = h.KEV.Ransomware
	}
	h.Prioridad, h.Motivo = riesgo.Decidir(s)
}

// ordenar: primero la prioridad; dentro de ella, las explotadas, luego por
// EPSS y por último por CVSS. Así el orden no depende solo de la gravedad.
func ordenar(hs []Hallazgo) {
	sort.SliceStable(hs, func(i, j int) bool {
		a, b := hs[i], hs[j]
		if a.Prioridad != b.Prioridad {
			return a.Prioridad < b.Prioridad
		}
		if (a.KEV != nil) != (b.KEV != nil) {
			return a.KEV != nil
		}
		ea, eb := probabilidad(a.EPSS), probabilidad(b.EPSS)
		if ea != eb {
			return ea > eb
		}
		if a.CVSS != b.CVSS {
			return a.CVSS > b.CVSS
		}
		if a.Paquete.Nombre != b.Paquete.Nombre {
			return a.Paquete.Nombre < b.Paquete.Nombre
		}
		return a.ID < b.ID
	})
}

func probabilidad(e *fuentes.EPSS) float64 {
	if e == nil {
		return -1
	}
	return e.Probabilidad
}

func cvesDe(v *fuentes.Vulnerabilidad) []string {
	var res []string
	vistos := map[string]bool{}
	for _, id := range append([]string{v.ID}, v.Aliases...) {
		if strings.HasPrefix(id, "CVE-") && !vistos[id] {
			vistos[id] = true
			res = append(res, id)
		}
	}
	sort.Strings(res)
	return res
}

func resumen(v *fuentes.Vulnerabilidad) string {
	if s := strings.TrimSpace(v.Summary); s != "" {
		return s
	}
	d := strings.TrimSpace(v.Details)
	if i := strings.IndexAny(d, "\n"); i >= 0 {
		d = d[:i]
	}
	if r := []rune(d); len(r) > 160 {
		d = string(r[:157]) + "..."
	}
	return d
}

// Actualizacion resume qué hacer con un paquete: a qué versión subirlo para
// cerrar todas sus vulnerabilidades que tienen arreglo.
type Actualizacion struct {
	Paquete       inventario.Paquete `json:"paquete"`
	Hasta         string             `json:"hasta,omitempty"`
	Arregla       int                `json:"arregla"`
	SinArreglo    int                `json:"sin_arreglo"`
	PeorPrioridad riesgo.Prioridad   `json:"peor_prioridad"`
}

// planActualizacion agrupa los hallazgos por paquete y fichero. La versión
// destino es la mayor de las versiones corregidas: la menor que las arregla
// todas. Va primero lo que cierra lo más urgente.
func planActualizacion(hs []Hallazgo) []Actualizacion {
	indice := map[string]int{}
	var res []Actualizacion
	for _, h := range hs {
		k := h.Paquete.Origen + "|" + h.Paquete.Clave()
		i, ok := indice[k]
		if !ok {
			i = len(res)
			indice[k] = i
			res = append(res, Actualizacion{Paquete: h.Paquete, PeorPrioridad: h.Prioridad})
		}
		a := &res[i]
		if h.Prioridad < a.PeorPrioridad {
			a.PeorPrioridad = h.Prioridad
		}
		if h.Arreglo == "" {
			a.SinArreglo++
			continue
		}
		a.Arregla++
		if a.Hasta == "" || compararVersiones(h.Arreglo, a.Hasta) > 0 {
			a.Hasta = h.Arreglo
		}
	}
	sort.SliceStable(res, func(i, j int) bool {
		if res[i].PeorPrioridad != res[j].PeorPrioridad {
			return res[i].PeorPrioridad < res[j].PeorPrioridad
		}
		if res[i].Arregla+res[i].SinArreglo != res[j].Arregla+res[j].SinArreglo {
			return res[i].Arregla+res[i].SinArreglo > res[j].Arregla+res[j].SinArreglo
		}
		return res[i].Paquete.Nombre < res[j].Paquete.Nombre
	})
	return res
}

// Filtrar deja solo los hallazgos de prioridad p o más urgentes y rehace el
// plan con ellos. El resumen por prioridad no cambia: sigue contando todo.
func (inf *Informe) Filtrar(p riesgo.Prioridad) {
	var quedan []Hallazgo
	for _, h := range inf.Hallazgos {
		if h.Prioridad <= p {
			quedan = append(quedan, h)
		}
	}
	inf.Ocultos = len(inf.Hallazgos) - len(quedan)
	inf.Hallazgos = quedan
	inf.Plan = planActualizacion(quedan)
}
