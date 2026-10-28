package informe

import (
	_ "embed"
	"html/template"
	"io"
	"time"

	"github.com/marnau74/triaje/internal/analisis"
	"github.com/marnau74/triaje/internal/riesgo"
)

//go:embed plantilla.html
var plantillaHTML string

var plantilla = template.Must(template.New("informe").Funcs(template.FuncMap{
	"cvss":   textoCVSS,
	"epss":   textoEPSS,
	"id":     identificador,
	"guion":  guion,
	"fecha":  func(t time.Time) string { return t.Local().Format("02/01/2006 15:04") },
	"plural": plural,
	"pct":    riesgo.Porcentaje,
}).Parse(plantillaHTML))

// pagina escribe un informe HTML de un solo fichero, sin nada externo, para
// adjuntarlo a un ticket o guardarlo como artefacto de la CI.
func pagina(w io.Writer, inf *analisis.Informe, version string) error {
	return plantilla.Execute(w, struct {
		*analisis.Informe
		Version string
	}{inf, version})
}
