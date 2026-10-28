package informe

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/marnau74/triaje/internal/analisis"
	"github.com/marnau74/triaje/internal/fuentes"
	"github.com/marnau74/triaje/internal/inventario"
	"github.com/marnau74/triaje/internal/riesgo"
)

func informeEjemplo() *analisis.Informe {
	lodash := inventario.Paquete{Ecosistema: inventario.NPM, Nombre: "lodash", Version: "4.17.4", Origen: "web/package-lock.json"}
	return &analisis.Informe{
		Generado: time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC),
		Ruta:     ".",
		Ficheros: []string{"web/package-lock.json"},
		Paquetes: 1,
		Resumen:  map[string]int{"P1": 1, "P2": 0, "P3": 0, "P4": 1},
		Fuentes:  map[string]string{"osv": "api.osv.dev"},
		Hallazgos: []analisis.Hallazgo{
			{
				Paquete: lodash, ID: "GHSA-1", CVEs: []string{"CVE-2023-0001"},
				// Los resúmenes vienen de fuera: el HTML tiene que escaparlos.
				Resumen: `XSS con <script>alert("hola")</script>`,
				CVSS:    6.1, EPSS: &fuentes.EPSS{Probabilidad: 0.0005, Percentil: 0.2, Fecha: "2026-10-27"},
				KEV:       &fuentes.EntradaKEV{CVE: "CVE-2023-0001", Nombre: "Prueba", Ransomware: true},
				Prioridad: riesgo.P1, Motivo: "se está explotando", Arreglo: "4.17.21",
				Enlace: "https://osv.dev/vulnerability/GHSA-1",
			},
			{
				Paquete: lodash, ID: "GHSA-2", Resumen: "Sin CVE", Prioridad: riesgo.P4, Motivo: "baja",
				Enlace: "https://osv.dev/vulnerability/GHSA-2",
			},
		},
		Plan: []analisis.Actualizacion{{Paquete: lodash, Hasta: "4.17.21", Arregla: 1, SinArreglo: 1, PeorPrioridad: riesgo.P1}},
	}
}

func TestSARIF(t *testing.T) {
	var b bytes.Buffer
	if err := Escribir(&b, "sarif", informeEjemplo(), "v1.0.0"); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Version string
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name  string
					Rules []struct {
						ID         string
						Properties map[string]any
					}
				}
			}
			Results []struct {
				RuleID    string
				RuleIndex int
				Level     string
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct{ URI string }
					}
				}
				PartialFingerprints map[string]string
			}
		}
	}
	if err := json.Unmarshal(b.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Version != "2.1.0" || len(doc.Runs) != 1 {
		t.Fatalf("SARIF mal formado: %s", b.String())
	}
	run := doc.Runs[0]
	if len(run.Tool.Driver.Rules) != 2 || len(run.Results) != 2 {
		t.Fatalf("reglas %d, resultados %d", len(run.Tool.Driver.Rules), len(run.Results))
	}
	if sev := run.Tool.Driver.Rules[0].Properties["security-severity"]; sev != "6.1" {
		t.Errorf("security-severity = %v, quiero \"6.1\"", sev)
	}
	if _, ok := run.Tool.Driver.Rules[1].Properties["security-severity"]; ok {
		t.Error("sin CVSS no debería inventarse security-severity")
	}
	r := run.Results[0]
	if r.Level != "error" || run.Results[1].Level != "note" {
		t.Errorf("niveles %q y %q", r.Level, run.Results[1].Level)
	}
	if r.Locations[0].PhysicalLocation.ArtifactLocation.URI != "web/package-lock.json" || r.PartialFingerprints["triaje/v1"] == "" {
		t.Errorf("ubicación o huella: %+v", r)
	}
	if run.Results[1].RuleIndex != 1 || run.Results[1].RuleID != "GHSA-2" {
		t.Errorf("ruleIndex no corresponde: %+v", run.Results[1])
	}
}

func TestHTML(t *testing.T) {
	var b bytes.Buffer
	if err := Escribir(&b, "html", informeEjemplo(), "v1.0.0"); err != nil {
		t.Fatal(err)
	}
	html := b.String()
	if strings.Contains(html, `<script>alert("hola")</script>`) {
		t.Error("el resumen no se ha escapado")
	}
	for _, quiero := range []string{"&lt;script&gt;", "Plan de actualización", "usada en ransomware", "0,1 %", "4.17.21", "triaje v1.0.0"} {
		if !strings.Contains(html, quiero) {
			t.Errorf("falta %q en el HTML", quiero)
		}
	}
}

func TestTablaVacia(t *testing.T) {
	inf := &analisis.Informe{Paquetes: 3, Ficheros: []string{"go.mod"}, Resumen: map[string]int{}}
	var b bytes.Buffer
	if err := Escribir(&b, "tabla", inf, ""); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "No hay vulnerabilidades conocidas") {
		t.Errorf("salida: %s", b.String())
	}
}
