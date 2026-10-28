// Package falso levanta un servidor que imita OSV, EPSS y KEV para los tests,
// para que no dependan de la red ni de que los datos reales cambien.
package falso

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/marnau74/triaje/internal/fuentes"
)

// Datos es lo que devuelve el servidor falso.
type Datos struct {
	// "ecosistema|nombre|version" -> ids de vulnerabilidades
	Afectados map[string][]string
	// id -> registro OSV en JSON
	Vulns map[string]string
	// CVE -> [probabilidad, percentil]
	EPSS map[string][2]string
	// CVE -> usada en ransomware
	KEV map[string]bool
	// si es true, EPSS responde 503
	EPSSCaido bool
}

type Servidor struct {
	*httptest.Server
	PeticionesKEV  atomic.Int32
	PeticionesEPSS atomic.Int32
}

// porPagina obliga a paginar en cuanto un paquete tiene más de dos
// vulnerabilidades, como hace OSV con los que tienen muchas.
const porPagina = 2

func Nuevo(t *testing.T, d Datos) *Servidor {
	s := &Servidor{}
	mux := http.NewServeMux()

	mux.HandleFunc("POST /v1/querybatch", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Queries []struct {
				Package   struct{ Name, Ecosystem string }
				Version   string
				PageToken string `json:"page_token"`
			}
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		type vuln struct {
			ID string `json:"id"`
		}
		type resultado struct {
			Vulns         []vuln `json:"vulns,omitempty"`
			NextPageToken string `json:"next_page_token,omitempty"`
		}
		var res []resultado
		for _, q := range req.Queries {
			ids := d.Afectados[q.Package.Ecosystem+"|"+q.Package.Name+"|"+q.Version]
			ini := 0
			if q.PageToken == "pagina2" {
				ini = porPagina
			}
			fin := min(ini+porPagina, len(ids))
			var r resultado
			for _, id := range ids[min(ini, len(ids)):fin] {
				r.Vulns = append(r.Vulns, vuln{id})
			}
			if fin < len(ids) {
				r.NextPageToken = "pagina2"
			}
			res = append(res, r)
		}
		json.NewEncoder(w).Encode(map[string]any{"results": res})
	})

	mux.HandleFunc("GET /v1/vulns/{id}", func(w http.ResponseWriter, r *http.Request) {
		v, ok := d.Vulns[r.PathValue("id")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte(v))
	})

	mux.HandleFunc("GET /epss", func(w http.ResponseWriter, r *http.Request) {
		s.PeticionesEPSS.Add(1)
		if d.EPSSCaido {
			http.Error(w, "caído", http.StatusServiceUnavailable)
			return
		}
		var data []map[string]string
		for _, cve := range strings.Split(r.URL.Query().Get("cve"), ",") {
			if e, ok := d.EPSS[cve]; ok {
				data = append(data, map[string]string{"cve": cve, "epss": e[0], "percentile": e[1], "date": "2026-10-27"})
			}
		}
		json.NewEncoder(w).Encode(map[string]any{"data": data})
	})

	mux.HandleFunc("GET /kev.json", func(w http.ResponseWriter, r *http.Request) {
		s.PeticionesKEV.Add(1)
		var vulns []map[string]string
		for cve, ransomware := range d.KEV {
			uso := "Unknown"
			if ransomware {
				uso = "Known"
			}
			vulns = append(vulns, map[string]string{
				"cveID": cve, "vulnerabilityName": "Vulnerabilidad de prueba", "dateAdded": "2023-10-10",
				"dueDate": "2023-10-31", "requiredAction": "Actualizar", "knownRansomwareCampaignUse": uso,
			})
		}
		json.NewEncoder(w).Encode(map[string]any{"catalogVersion": "2026.10.27", "vulnerabilities": vulns})
	})

	s.Server = httptest.NewServer(mux)
	t.Cleanup(s.Close)
	return s
}

// Cliente apunta un cliente de fuentes a este servidor, sin caché.
func (s *Servidor) Cliente() *fuentes.Cliente {
	c := fuentes.NuevoCliente()
	c.HTTP = s.Client()
	c.OSVURL = s.URL
	c.EPSSURL = s.URL + "/epss"
	c.KEVURL = s.URL + "/kev.json"
	return c
}
