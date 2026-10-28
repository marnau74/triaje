// Package informe escribe el resultado del análisis en los formatos de
// salida: tabla para la terminal, JSON, SARIF (code scanning de GitHub) y
// una página HTML autocontenida.
package informe

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/marnau74/triaje/internal/analisis"
	"github.com/marnau74/triaje/internal/riesgo"
)

var Formatos = []string{"tabla", "json", "sarif", "html"}

func Escribir(w io.Writer, formato string, inf *analisis.Informe, version string) error {
	switch formato {
	case "tabla":
		return tabla(w, inf)
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		enc.SetEscapeHTML(false)
		return enc.Encode(inf)
	case "sarif":
		return sarif(w, inf, version)
	case "html":
		return pagina(w, inf, version)
	}
	return fmt.Errorf("formato desconocido %q (usa %s)", formato, strings.Join(Formatos, ", "))
}

func tabla(w io.Writer, inf *analisis.Informe) error {
	total := len(inf.Hallazgos) + inf.Ocultos
	fmt.Fprintf(w, "%d paquetes en %d %s · %d %s\n",
		inf.Paquetes, len(inf.Ficheros), plural(len(inf.Ficheros), "fichero", "ficheros"),
		total, plural(total, "vulnerabilidad", "vulnerabilidades"))
	for _, a := range inf.Avisos {
		fmt.Fprintf(w, "aviso: %s\n", a)
	}
	if total == 0 {
		fmt.Fprintln(w, "No hay vulnerabilidades conocidas en estas versiones.")
		return nil
	}
	fmt.Fprintf(w, "P1 urgente: %d · P2 alta: %d · P3 media: %d · P4 baja: %d\n",
		inf.Resumen["P1"], inf.Resumen["P2"], inf.Resumen["P3"], inf.Resumen["P4"])
	if inf.Ocultos > 0 {
		fmt.Fprintf(w, "(se muestran %d; las %d de prioridad más baja quedan fuera)\n", len(inf.Hallazgos), inf.Ocultos)
	}
	if len(inf.Hallazgos) == 0 {
		return nil
	}

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "\nPlan de actualización")
	fmt.Fprintln(tw, "PRIO\tPAQUETE\tFICHERO\tDE\tA\tCIERRA")
	for _, a := range inf.Plan {
		cierra := fmt.Sprint(a.Arregla)
		if a.SinArreglo > 0 {
			cierra += fmt.Sprintf(" (+%d sin arreglo publicado)", a.SinArreglo)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", a.PeorPrioridad, a.Paquete.Nombre, a.Paquete.Origen,
			a.Paquete.Version, guion(a.Hasta), cierra)
	}
	if err := tw.Flush(); err != nil {
		return err
	}

	fmt.Fprintln(w, "\nVulnerabilidades, de más a menos urgente")
	fmt.Fprintln(tw, "PRIO\tPAQUETE\tVERSIÓN\tARREGLO\tVULNERABILIDAD\tCVSS\tEPSS\tKEV\tMOTIVO")
	for _, h := range inf.Hallazgos {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			h.Prioridad, h.Paquete.Nombre, h.Paquete.Version, guion(h.Arreglo),
			identificador(h), textoCVSS(h), textoEPSS(h), siNo(h.KEV != nil), h.Motivo)
	}
	return tw.Flush()
}

// identificador muestra la CVE si la hay, que es por lo que la gente busca.
func identificador(h analisis.Hallazgo) string {
	if len(h.CVEs) > 0 {
		return h.CVEs[0]
	}
	return h.ID
}

func textoCVSS(h analisis.Hallazgo) string {
	if h.CVSS == 0 {
		return "—"
	}
	s := strings.Replace(fmt.Sprintf("%.1f", h.CVSS), ".", ",", 1)
	if h.CVSSAproximado {
		s = "≈" + s
	}
	return s
}

func textoEPSS(h analisis.Hallazgo) string {
	if h.EPSS == nil {
		return "—"
	}
	return riesgo.Porcentaje(h.EPSS.Probabilidad)
}

func guion(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

func siNo(b bool) string {
	if b {
		return "sí"
	}
	return "no"
}

func plural(n int, uno, varios string) string {
	if n == 1 {
		return uno
	}
	return varios
}

// nivelSARIF: GitHub enseña "error" en rojo, "warning" en amarillo y "note"
// en gris; se corresponde con la urgencia, no con la gravedad CVSS.
func nivelSARIF(p riesgo.Prioridad) string {
	switch p {
	case riesgo.P1, riesgo.P2:
		return "error"
	case riesgo.P3:
		return "warning"
	}
	return "note"
}
