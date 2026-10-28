package analisis

import (
	"context"
	"strings"
	"testing"

	"github.com/marnau74/triaje/internal/falso"
	"github.com/marnau74/triaje/internal/fuentes"
	"github.com/marnau74/triaje/internal/inventario"
	"github.com/marnau74/triaje/internal/riesgo"
)

// Escenario: un paquete npm con cuatro vulnerabilidades (obliga a paginar),
// una de ellas en KEV y otra duplicada en dos bases de datos, y un paquete
// Go sin CVE ni CVSS.
var datosEjemplo = falso.Datos{
	Afectados: map[string][]string{
		"npm|lodash|4.17.4": {"GHSA-kev", "GHSA-epss", "GHSA-duplicada", "OSV-duplicada"},
		"Go|stdlib|1.21.0":  {"GO-2024-0001"},
		"npm|limpio|1.0.0":  nil,
	},
	Vulns: map[string]string{
		"GHSA-kev": `{"id": "GHSA-kev", "summary": "Explotada", "aliases": ["CVE-2023-0001"],
			"severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L"}],
			"affected": [{"package": {"ecosystem": "npm", "name": "lodash"},
				"ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.12"}]}]}]}`,
		"GHSA-epss": `{"id": "GHSA-epss", "summary": "Con EPSS alto", "aliases": ["CVE-2023-0002"],
			"severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
			"affected": [{"package": {"ecosystem": "npm", "name": "lodash"},
				"ranges": [{"type": "SEMVER", "events": [{"introduced": "4.0.0"}, {"fixed": "4.17.21"}]}]}]}`,
		"GHSA-duplicada": `{"id": "GHSA-duplicada", "summary": "La misma en GitHub", "aliases": ["CVE-2023-0003"],
			"database_specific": {"severity": "MODERATE"},
			"affected": [{"package": {"ecosystem": "npm", "name": "lodash"}}]}`,
		"OSV-duplicada": `{"id": "OSV-duplicada", "summary": "La misma en otra base", "aliases": ["CVE-2023-0003", "GHSA-duplicada"],
			"severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N"}],
			"affected": [{"package": {"ecosystem": "npm", "name": "lodash"}}]}`,
		"GO-2024-0001": `{"id": "GO-2024-0001", "details": "Primera línea del detalle.\nSegunda línea.",
			"affected": [{"package": {"ecosystem": "Go", "name": "stdlib"},
				"ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.21.5"}, {"introduced": "1.22.0"}, {"fixed": "1.22.1"}]}]}]}`,
	},
	EPSS: map[string][2]string{
		"CVE-2023-0001": {"0.003", "0.70"},
		"CVE-2023-0002": {"0.45", "0.99"},
		"CVE-2023-0003": {"0.0004", "0.10"},
	},
	KEV: map[string]bool{"CVE-2023-0001": true},
}

var paquetesEjemplo = []inventario.Paquete{
	{Ecosistema: inventario.NPM, Nombre: "lodash", Version: "4.17.4", Origen: "web/package-lock.json"},
	{Ecosistema: inventario.Go, Nombre: "stdlib", Version: "1.21.0", Origen: "go.mod"},
	{Ecosistema: inventario.NPM, Nombre: "limpio", Version: "1.0.0", Origen: "web/package-lock.json"},
}

func TestAnalizar(t *testing.T) {
	srv := falso.Nuevo(t, datosEjemplo)
	inf, err := Analizar(context.Background(), srv.Cliente(), ".", paquetesEjemplo)
	if err != nil {
		t.Fatal(err)
	}

	type fila struct {
		id, prioridad, arreglo string
		kev                    bool
	}
	var got []fila
	for _, h := range inf.Hallazgos {
		got = append(got, fila{h.ID, h.Prioridad.String(), h.Arreglo, h.KEV != nil})
	}
	// Orden por prioridad, no por CVSS: la de CVSS 5,3 en KEV va antes que
	// la de 9,8, y la duplicada sale una sola vez (con su vector CVSS 3).
	quiero := []fila{
		{"GHSA-kev", "P1", "4.17.12", true},
		{"GHSA-epss", "P2", "4.17.21", false},
		{"GO-2024-0001", "P3", "1.21.5", false},
		{"OSV-duplicada", "P4", "", false},
	}
	if len(got) != len(quiero) {
		t.Fatalf("hallazgos:\n got   %v\n quiero %v", got, quiero)
	}
	for i := range quiero {
		if got[i] != quiero[i] {
			t.Errorf("hallazgo %d: got %v, quiero %v", i, got[i], quiero[i])
		}
	}

	stdlib := inf.Hallazgos[2]
	if stdlib.Resumen != "Primera línea del detalle." {
		t.Errorf("sin summary se usa la primera línea del detalle; got %q", stdlib.Resumen)
	}
	if !strings.Contains(stdlib.Motivo, "a mano") {
		t.Errorf("sin CVSS ni EPSS el motivo debería pedir revisarla; got %q", stdlib.Motivo)
	}
	dup := inf.Hallazgos[3]
	if dup.CVSS != 2.6 || dup.CVSSAproximado {
		t.Errorf("la duplicada debería quedarse con el CVSS calculado del vector; got %v aprox=%v", dup.CVSS, dup.CVSSAproximado)
	}

	if inf.Resumen["P1"] != 1 || inf.Resumen["P2"] != 1 || inf.Resumen["P3"] != 1 || inf.Resumen["P4"] != 1 {
		t.Errorf("resumen %v", inf.Resumen)
	}
	if len(inf.Avisos) != 0 {
		t.Errorf("avisos inesperados: %v", inf.Avisos)
	}

	// El plan sube lodash a la mayor versión corregida y cuenta la que no tiene arreglo.
	if len(inf.Plan) != 2 {
		t.Fatalf("plan %+v", inf.Plan)
	}
	if p := inf.Plan[0]; p.Paquete.Nombre != "lodash" || p.Hasta != "4.17.21" || p.Arregla != 2 || p.SinArreglo != 1 || p.PeorPrioridad != riesgo.P1 {
		t.Errorf("plan de lodash %+v", p)
	}

	inf.Filtrar(riesgo.P2)
	if len(inf.Hallazgos) != 2 || inf.Ocultos != 2 || len(inf.Plan) != 1 || inf.Plan[0].SinArreglo != 0 {
		t.Errorf("tras filtrar a P2: %d hallazgos, %d ocultos, plan %+v", len(inf.Hallazgos), inf.Ocultos, inf.Plan)
	}
}

func TestAnalizarSinEPSS(t *testing.T) {
	d := datosEjemplo
	d.EPSSCaido = true
	srv := falso.Nuevo(t, d)
	inf, err := Analizar(context.Background(), srv.Cliente(), ".", paquetesEjemplo)
	if err != nil {
		t.Fatal(err)
	}
	if len(inf.Avisos) != 1 || !strings.Contains(inf.Avisos[0], "EPSS") {
		t.Errorf("debería avisar de que EPSS no está: %v", inf.Avisos)
	}
	// KEV sigue funcionando; la de CVSS 9,8 sin EPSS sube a P2 por prudencia.
	if inf.Hallazgos[0].Prioridad != riesgo.P1 || inf.Hallazgos[1].Prioridad != riesgo.P2 {
		t.Errorf("prioridades sin EPSS: %s, %s", inf.Hallazgos[0].Prioridad, inf.Hallazgos[1].Prioridad)
	}
}

func TestCacheKEV(t *testing.T) {
	srv := falso.Nuevo(t, datosEjemplo)
	c := srv.Cliente()
	c.Cache = &fuentes.Cache{Carpeta: t.TempDir()}
	for range 3 {
		if _, err := c.CatalogoKEV(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if n := srv.PeticionesKEV.Load(); n != 1 {
		t.Errorf("el catálogo KEV se ha descargado %d veces; con caché debería ser 1", n)
	}

	// Sin red se usa la copia guardada, aunque esté caducada.
	srv.Close()
	kev, err := c.CatalogoKEV(context.Background())
	if err != nil || len(kev) != 1 {
		t.Errorf("sin red debería usar la caché: %v, %d entradas", err, len(kev))
	}
}
