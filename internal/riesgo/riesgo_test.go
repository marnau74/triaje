package riesgo

import (
	"strings"
	"testing"
)

// Los valores esperados son los de la calculadora oficial de FIRST
// (https://www.first.org/cvss/calculator/3.1).
func TestPuntuacionCVSS3(t *testing.T) {
	casos := []struct {
		vector string
		quiero float64
	}{
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1}, // XSS típico
		{"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L", 5.3},
		{"CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N", 2.6},
		{"CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", 0},
		{"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", 9.9},
		{"CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N", 4.8}, // PR:H con alcance cambiado vale 0.5
		{"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:L/I:L/A:N", 5.5},
		// El orden de las métricas no importa y las temporales se ignoran.
		{"CVSS:3.1/C:H/I:H/A:H/AV:N/AC:L/PR:N/UI:N/S:U/E:P/RL:O", 9.8},
	}
	for _, c := range casos {
		got, err := PuntuacionCVSS3(c.vector)
		if err != nil {
			t.Errorf("%s: error inesperado %v", c.vector, err)
			continue
		}
		if got != c.quiero {
			t.Errorf("%s = %.1f, quiero %.1f", c.vector, got, c.quiero)
		}
	}
}

func TestPuntuacionCVSS3Errores(t *testing.T) {
	for _, v := range []string{
		"",
		"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/C:H/I:H/A:H", // falta S
		"CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H",
		"CVSS:3.1/AVN",
	} {
		if _, err := PuntuacionCVSS3(v); err == nil {
			t.Errorf("%q debería dar error", v)
		}
	}
}

func TestRedondearArriba(t *testing.T) {
	casos := map[float64]float64{4.0: 4.0, 4.000000001: 4.0, 4.02: 4.1, 4.1: 4.1, 9.71: 9.8, 0: 0}
	for x, quiero := range casos {
		if got := redondearArriba(x); got != quiero {
			t.Errorf("redondearArriba(%v) = %v, quiero %v", x, got, quiero)
		}
	}
}

func TestDecidir(t *testing.T) {
	casos := []struct {
		nombre string
		s      Senales
		quiero Prioridad
		motivo string // un trozo que debe aparecer
	}{
		{"en KEV aunque sea leve", Senales{CVSS: 3.1, CVSSConocido: true, EPSS: 0.001, EPSSConocido: true, EnKEV: true}, P1, "KEV"},
		{"KEV con ransomware", Senales{EnKEV: true, Ransomware: true}, P1, "ransomware"},
		{"EPSS alto con gravedad media", Senales{CVSS: 5.3, CVSSConocido: true, EPSS: 0.92, EPSSConocido: true}, P2, "EPSS 92,0 %"},
		{"EPSS justo en el umbral", Senales{EPSS: EPSSAlto, EPSSConocido: true}, P2, ""},
		{"crítica y EPSS apreciable", Senales{CVSS: 9.8, CVSSConocido: true, EPSS: 0.02, EPSSConocido: true}, P2, "crítica"},
		{"crítica sin EPSS", Senales{CVSS: 9.1, CVSSConocido: true}, P2, "sin dato de EPSS"},
		{"crítica que nadie explota", Senales{CVSS: 9.8, CVSSConocido: true, EPSS: 0.004, EPSSConocido: true}, P3, "poca probabilidad"},
		{"alta sin EPSS", Senales{CVSS: 7.5, CVSSConocido: true}, P3, ""},
		{"media con EPSS apreciable", Senales{CVSS: 5.0, CVSSConocido: true, EPSS: 0.03, EPSSConocido: true}, P3, "apreciable"},
		{"sin ningún dato", Senales{}, P3, "a mano"},
		{"media e improbable", Senales{CVSS: 5.3, CVSSConocido: true, EPSS: 0.0005, EPSSConocido: true}, P4, "EPSS <0,1 %"},
		{"EPSS casi seguro", Senales{EPSS: 0.99995, EPSSConocido: true}, P2, "EPSS >99,9 %"},
		{"media sin EPSS", Senales{CVSS: 4.0, CVSSConocido: true}, P4, ""},
		{"sin CVSS e improbable", Senales{EPSS: 0.002, EPSSConocido: true}, P4, ""},
	}
	for _, c := range casos {
		t.Run(c.nombre, func(t *testing.T) {
			p, motivo := Decidir(c.s)
			if p != c.quiero {
				t.Errorf("prioridad %s, quiero %s (motivo: %s)", p, c.quiero, motivo)
			}
			if !strings.Contains(motivo, c.motivo) {
				t.Errorf("motivo %q no contiene %q", motivo, c.motivo)
			}
		})
	}
}

func TestParsePrioridad(t *testing.T) {
	for s, quiero := range map[string]Prioridad{"p1": P1, "P2": P2, " p3 ": P3, "p4": P4} {
		if got, err := ParsePrioridad(s); err != nil || got != quiero {
			t.Errorf("ParsePrioridad(%q) = %v, %v", s, got, err)
		}
	}
	for _, s := range []string{"", "p0", "p5", "alta"} {
		if _, err := ParsePrioridad(s); err == nil {
			t.Errorf("ParsePrioridad(%q) debería dar error", s)
		}
	}
}
