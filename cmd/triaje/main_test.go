package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marnau74/triaje/internal/falso"
)

// Un proyecto con una vulnerabilidad P2 (EPSS alto) y otra P4.
func proyecto(t *testing.T) (string, *falso.Servidor) {
	dir := t.TempDir()
	lock := `{"lockfileVersion": 3, "packages": {"node_modules/lodash": {"version": "4.17.4"}}}`
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(lock), 0o644); err != nil {
		t.Fatal(err)
	}
	srv := falso.Nuevo(t, falso.Datos{
		Afectados: map[string][]string{"npm|lodash|4.17.4": {"GHSA-alta", "GHSA-baja"}},
		Vulns: map[string]string{
			"GHSA-alta": `{"id": "GHSA-alta", "summary": "Alta", "aliases": ["CVE-2023-0002"],
				"severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
				"affected": [{"package": {"ecosystem": "npm", "name": "lodash"},
					"ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}]}]}`,
			"GHSA-baja": `{"id": "GHSA-baja", "summary": "Baja", "aliases": ["CVE-2023-0003"],
				"severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N"}],
				"affected": [{"package": {"ecosystem": "npm", "name": "lodash"}}]}`,
		},
		EPSS: map[string][2]string{"CVE-2023-0002": {"0.45", "0.99"}, "CVE-2023-0003": {"0.0004", "0.1"}},
	})
	return dir, srv
}

func correr(t *testing.T, srv *falso.Servidor, args ...string) (int, string, string) {
	t.Helper()
	var salida, errores bytes.Buffer
	codigo := ejecutar(context.Background(), append([]string{"-sin-cache"}, args...), &salida, &errores, srv.Cliente())
	return codigo, salida.String(), errores.String()
}

func TestCodigosDeSalida(t *testing.T) {
	dir, srv := proyecto(t)
	casos := []struct {
		args   []string
		codigo int
	}{
		{[]string{dir}, salidaBien},
		{[]string{"-fallar-en", "p1", dir}, salidaBien},
		{[]string{"-fallar-en", "p2", dir}, salidaUmbral},
		{[]string{"-fallar-en", "P4", dir}, salidaUmbral},
		// -solo oculta, pero no cambia lo que hace fallar.
		{[]string{"-solo", "p1", "-fallar-en", "p2", dir}, salidaUmbral},
		{[]string{"-fallar-en", "p9", dir}, salidaError},
		{[]string{"-formato", "xml", dir}, salidaError},
		{[]string{filepath.Join(dir, "no-existe")}, salidaError},
		{[]string{dir, dir}, salidaError},
	}
	for _, c := range casos {
		codigo, _, errores := correr(t, srv, c.args...)
		if codigo != c.codigo {
			t.Errorf("%v: código %d, quiero %d (%s)", c.args, codigo, c.codigo, errores)
		}
	}
}

func TestSalidaTabla(t *testing.T) {
	dir, srv := proyecto(t)
	_, salida, _ := correr(t, srv, dir)
	for _, quiero := range []string{
		"1 paquetes en 1 fichero · 2 vulnerabilidades",
		"P1 urgente: 0 · P2 alta: 1 · P3 media: 0 · P4 baja: 1",
		"Plan de actualización",
		"4.17.4  4.17.21  1 (+1 sin arreglo publicado)",
		"explotación poco probable (EPSS <0,1 %)",
		"CVE-2023-0002",
		"45,0 %",
	} {
		if !strings.Contains(salida, quiero) {
			t.Errorf("falta %q en la salida:\n%s", quiero, salida)
		}
	}

	_, salida, _ = correr(t, srv, "-solo", "p2", dir)
	if strings.Contains(salida, "CVE-2023-0003") || !strings.Contains(salida, "las 1 de prioridad más baja quedan fuera") {
		t.Errorf("con -solo p2 la P4 no debería salir:\n%s", salida)
	}
}

func TestSalidaFichero(t *testing.T) {
	dir, srv := proyecto(t)
	destino := filepath.Join(t.TempDir(), "informe.json")
	codigo, salida, errores := correr(t, srv, "-formato", "json", "-salida", destino, dir)
	if codigo != salidaBien || salida != "" || !strings.Contains(errores, "P2 1") {
		t.Fatalf("código %d, salida %q, errores %q", codigo, salida, errores)
	}
	datos, err := os.ReadFile(destino)
	if err != nil {
		t.Fatal(err)
	}
	var inf struct {
		Hallazgos []struct {
			Prioridad string `json:"prioridad"`
			EPSS      struct {
				Probabilidad float64 `json:"probabilidad"`
			} `json:"epss"`
		} `json:"hallazgos"`
	}
	if err := json.Unmarshal(datos, &inf); err != nil {
		t.Fatal(err)
	}
	if len(inf.Hallazgos) != 2 || inf.Hallazgos[0].Prioridad != "P2" || inf.Hallazgos[0].EPSS.Probabilidad != 0.45 {
		t.Errorf("JSON inesperado: %s", datos)
	}
}

func TestVersion(t *testing.T) {
	_, srv := proyecto(t)
	codigo, salida, _ := correr(t, srv, "-version")
	if codigo != salidaBien || !strings.HasPrefix(salida, "triaje ") {
		t.Errorf("código %d, salida %q", codigo, salida)
	}
}
