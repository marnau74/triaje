package informe

import (
	"encoding/json"
	"fmt"
	"io"
	"strconv"

	"github.com/marnau74/triaje/internal/analisis"
)

// sarif escribe SARIF 2.1.0 con lo que GitHub code scanning necesita: una
// regla por vulnerabilidad con security-severity (para su escala de gravedad)
// y un resultado por paquete afectado, situado en su fichero de dependencias.
func sarif(w io.Writer, inf *analisis.Informe, version string) error {
	type obj = map[string]any
	var reglas []obj
	indice := map[string]int{}
	var resultados []obj

	for _, h := range inf.Hallazgos {
		if _, ok := indice[h.ID]; !ok {
			indice[h.ID] = len(reglas)
			props := obj{"tags": []string{"security", "vulnerability", string(h.Paquete.Ecosistema)}}
			if h.CVSS > 0 {
				props["security-severity"] = strconv.FormatFloat(h.CVSS, 'f', 1, 64)
			}
			reglas = append(reglas, obj{
				"id":               h.ID,
				"name":             h.ID,
				"shortDescription": obj{"text": h.Resumen},
				"helpUri":          h.Enlace,
				"help":             obj{"text": h.Resumen + "\n\n" + h.Enlace},
				"properties":       props,
			})
		}
		mensaje := fmt.Sprintf("%s %s %s: %s. Prioridad %s (%s): %s.",
			h.Paquete.Nombre, h.Paquete.Version, identificador(h), h.Resumen, h.Prioridad, h.Prioridad.Nombre(), h.Motivo)
		if h.Arreglo != "" {
			mensaje += " Actualiza a " + h.Arreglo + " o posterior."
		}
		resultados = append(resultados, obj{
			"ruleId":    h.ID,
			"ruleIndex": indice[h.ID],
			"level":     nivelSARIF(h.Prioridad),
			"message":   obj{"text": mensaje},
			"locations": []obj{{
				"physicalLocation": obj{
					"artifactLocation": obj{"uri": h.Paquete.Origen},
					"region":           obj{"startLine": 1},
				},
			}},
			// Sin huella estable GitHub cerraría y reabriría la alerta en
			// cada análisis.
			"partialFingerprints": obj{
				"triaje/v1": h.ID + "|" + string(h.Paquete.Ecosistema) + "|" + h.Paquete.Nombre + "|" + h.Paquete.Origen,
			},
			"properties": obj{"prioridad": h.Prioridad.String()},
		})
	}
	if reglas == nil {
		reglas = []obj{}
	}
	if resultados == nil {
		resultados = []obj{}
	}

	doc := obj{
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"version": "2.1.0",
		"runs": []obj{{
			"tool": obj{"driver": obj{
				"name":           "triaje",
				"version":        version,
				"informationUri": "https://github.com/marnau74/triaje",
				"rules":          reglas,
			}},
			"results": resultados,
		}},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(doc)
}
