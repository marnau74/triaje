package analisis

import (
	"encoding/json"
	"testing"

	"github.com/marnau74/triaje/internal/fuentes"
	"github.com/marnau74/triaje/internal/inventario"
)

func TestCompararVersiones(t *testing.T) {
	casos := []struct {
		a, b   string
		quiero int
	}{
		{"1.2.3", "1.2.3", 0},
		{"1.2.10", "1.2.9", 1},
		{"1.10", "1.9.9", 1},
		{"v1.2.3", "1.2.3", 0},
		{"1.2", "1.2.0", 0},
		{"1.2.1", "1.2", 1},
		{"1.2.0-rc1", "1.2.0", -1},
		{"1.2.0b1", "1.2.0", -1}, // PEP 440
		{"1.2.0-alpha", "1.2.0-beta", -1},
		{"1.2.0+build5", "1.2.0", 0},
		{"4.2.24", "3.2.25", 1},
		{"2.0.0", "10.0.0", -1},
	}
	for _, c := range casos {
		if got := compararVersiones(c.a, c.b); got != c.quiero {
			t.Errorf("compararVersiones(%q, %q) = %d, quiero %d", c.a, c.b, got, c.quiero)
		}
		if got := compararVersiones(c.b, c.a); got != -c.quiero {
			t.Errorf("compararVersiones(%q, %q) = %d, quiero %d", c.b, c.a, got, -c.quiero)
		}
	}
}

func vuln(t *testing.T, js string) *fuentes.Vulnerabilidad {
	t.Helper()
	var v fuentes.Vulnerabilidad
	if err := json.Unmarshal([]byte(js), &v); err != nil {
		t.Fatal(err)
	}
	return &v
}

func TestVersionArreglada(t *testing.T) {
	// Django: la rama 3.2 tiene arreglo, la 4.2 también; para la 3.2.0
	// instalada la primera versión corregida posterior es 3.2.14.
	v := vuln(t, `{"id": "X", "affected": [
		{"package": {"ecosystem": "PyPI", "name": "Django"}, "ranges": [
			{"type": "GIT", "events": [{"introduced": "0"}, {"fixed": "abc123"}]},
			{"type": "ECOSYSTEM", "events": [{"introduced": "4.0"}, {"fixed": "4.0.6"}, {"introduced": "3.2"}, {"fixed": "3.2.14"}]}]},
		{"package": {"ecosystem": "PyPI", "name": "otro"}, "ranges": [
			{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "3.2.1"}]}]}]}`)
	p := inventario.Paquete{Ecosistema: inventario.PyPI, Nombre: "django", Version: "3.2.0"}
	if got := versionArreglada(v, p); got != "3.2.14" {
		t.Errorf("got %q, quiero 3.2.14", got)
	}
	p.Version = "3.2.20"
	if got := versionArreglada(v, p); got != "4.0.6" {
		t.Errorf("con 3.2.20 got %q, quiero 4.0.6", got)
	}
	p.Version = "5.0"
	if got := versionArreglada(v, p); got != "" {
		t.Errorf("sin arreglo posterior got %q", got)
	}
}

func TestGravedad(t *testing.T) {
	casos := []struct {
		js        string
		puntos    float64
		aprox     bool
		conVector bool
	}{
		{`{"severity": [{"type": "CVSS_V4", "score": "CVSS:4.0/AV:N"}, {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}`, 9.8, false, true},
		{`{"severity": [{"type": "CVSS_V4", "score": "CVSS:4.0/AV:N"}], "database_specific": {"severity": "HIGH"}}`, 7.5, true, false},
		{`{"database_specific": {"severity": "critical"}}`, 9.0, true, false},
		{`{}`, 0, false, false},
	}
	for _, c := range casos {
		p, vector, aprox := gravedad(vuln(t, c.js))
		if p != c.puntos || aprox != c.aprox || (vector != "") != c.conVector {
			t.Errorf("%s: got %v %q %v", c.js, p, vector, aprox)
		}
	}
}
