// Package fuentes consulta las tres fuentes públicas que usa triaje:
// OSV (qué vulnerabilidades afectan a cada paquete), EPSS (probabilidad de
// que se explote en los próximos 30 días) y el catálogo KEV de CISA
// (vulnerabilidades que ya se están explotando).
package fuentes

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/marnau74/triaje/internal/inventario"
)

// Cliente agrupa las direcciones de las fuentes para poder cambiarlas en los
// tests (o apuntar a un espejo interno).
type Cliente struct {
	HTTP    *http.Client
	OSVURL  string
	EPSSURL string
	KEVURL  string
	Cache   *Cache // nil = sin caché
}

func NuevoCliente() *Cliente {
	return &Cliente{
		HTTP:    &http.Client{Timeout: 30 * time.Second},
		OSVURL:  "https://api.osv.dev",
		EPSSURL: "https://api.first.org/data/v1/epss",
		KEVURL:  "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
	}
}

// Vulnerabilidad es la parte del formato OSV que usa triaje.
type Vulnerabilidad struct {
	ID       string   `json:"id"`
	Summary  string   `json:"summary"`
	Details  string   `json:"details"`
	Aliases  []string `json:"aliases"`
	Severity []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	Affected []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		Ranges []struct {
			Type   string              `json:"type"`
			Events []map[string]string `json:"events"`
		} `json:"ranges"`
		DatabaseSpecific map[string]any `json:"database_specific"`
	} `json:"affected"`
	DatabaseSpecific map[string]any `json:"database_specific"`
	References       []struct {
		Type string `json:"type"`
		URL  string `json:"url"`
	} `json:"references"`
}

// tamaño máximo de lote que acepta /v1/querybatch.
const loteOSV = 1000

// BuscarVulnerabilidades devuelve, para cada paquete (por su Clave), los
// identificadores de las vulnerabilidades que le afectan, y el detalle de
// cada una de ellas.
func (c *Cliente) BuscarVulnerabilidades(ctx context.Context, ps []inventario.Paquete) (map[string][]string, map[string]*Vulnerabilidad, error) {
	// Un mismo paquete puede aparecer en varios ficheros: se pregunta una vez.
	var unicos []inventario.Paquete
	vistos := map[string]bool{}
	for _, p := range ps {
		if !vistos[p.Clave()] {
			vistos[p.Clave()] = true
			unicos = append(unicos, p)
		}
	}

	idsPorPaquete := map[string][]string{}
	for ini := 0; ini < len(unicos); ini += loteOSV {
		fin := min(ini+loteOSV, len(unicos))
		if err := c.consultarLote(ctx, unicos[ini:fin], idsPorPaquete); err != nil {
			return nil, nil, err
		}
	}

	detalles, err := c.detalles(ctx, idsPorPaquete)
	if err != nil {
		return nil, nil, err
	}
	return idsPorPaquete, detalles, nil
}

type consultaOSV struct {
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
	Version   string `json:"version"`
	PageToken string `json:"page_token,omitempty"`
}

func (c *Cliente) consultarLote(ctx context.Context, lote []inventario.Paquete, res map[string][]string) error {
	pendientes := make([]consultaOSV, len(lote))
	paquetes := append([]inventario.Paquete(nil), lote...)
	for i, p := range lote {
		pendientes[i].Package.Name = p.Nombre
		pendientes[i].Package.Ecosystem = string(p.Ecosistema)
		pendientes[i].Version = p.Version
	}
	// OSV pagina los paquetes con muchas vulnerabilidades: se repiten solo esas
	// consultas con su next_page_token hasta que no quede ninguna.
	for len(pendientes) > 0 {
		var resp struct {
			Results []struct {
				Vulns []struct {
					ID string `json:"id"`
				} `json:"vulns"`
				NextPageToken string `json:"next_page_token"`
			} `json:"results"`
		}
		if err := c.postJSON(ctx, c.OSVURL+"/v1/querybatch", map[string]any{"queries": pendientes}, &resp); err != nil {
			return fmt.Errorf("OSV: %w", err)
		}
		if len(resp.Results) != len(pendientes) {
			return fmt.Errorf("OSV: esperaba %d resultados y han llegado %d", len(pendientes), len(resp.Results))
		}
		var sigConsultas []consultaOSV
		var sigPaquetes []inventario.Paquete
		for i, r := range resp.Results {
			clave := paquetes[i].Clave()
			for _, v := range r.Vulns {
				res[clave] = append(res[clave], v.ID)
			}
			if r.NextPageToken != "" {
				q := pendientes[i]
				q.PageToken = r.NextPageToken
				sigConsultas = append(sigConsultas, q)
				sigPaquetes = append(sigPaquetes, paquetes[i])
			}
		}
		pendientes, paquetes = sigConsultas, sigPaquetes
	}
	return nil
}

// detalles descarga cada vulnerabilidad una sola vez, con varias peticiones en
// paralelo pero acotadas para no saturar la API.
func (c *Cliente) detalles(ctx context.Context, idsPorPaquete map[string][]string) (map[string]*Vulnerabilidad, error) {
	ids := map[string]bool{}
	for _, l := range idsPorPaquete {
		for _, id := range l {
			ids[id] = true
		}
	}
	res := make(map[string]*Vulnerabilidad, len(ids))
	var (
		mu      sync.Mutex
		wg      sync.WaitGroup
		primero error
	)
	sem := make(chan struct{}, 8)
	for id := range ids {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			var v Vulnerabilidad
			err := c.getJSON(ctx, c.OSVURL+"/v1/vulns/"+url.PathEscape(id), &v)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				if primero == nil {
					primero = fmt.Errorf("OSV %s: %w", id, err)
				}
				return
			}
			res[id] = &v
		}(id)
	}
	wg.Wait()
	return res, primero
}

func (c *Cliente) postJSON(ctx context.Context, dir string, cuerpo, destino any) error {
	b, err := json.Marshal(cuerpo)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, dir, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	return c.hacer(req, destino)
}

func (c *Cliente) getJSON(ctx context.Context, dir string, destino any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, dir, nil)
	if err != nil {
		return err
	}
	return c.hacer(req, destino)
}

// hacer manda la petición, con un par de reintentos si el servidor está
// saturado o falla, y decodifica la respuesta JSON.
func (c *Cliente) hacer(req *http.Request, destino any) error {
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "triaje (+https://github.com/marnau74/triaje)")
	var ultimo error
	for intento := 0; intento < 3; intento++ {
		if intento > 0 {
			select {
			case <-req.Context().Done():
				return req.Context().Err()
			case <-time.After(time.Duration(intento) * time.Second):
			}
			if req.GetBody != nil {
				cuerpo, err := req.GetBody()
				if err != nil {
					return err
				}
				req.Body = cuerpo
			}
		}
		resp, err := c.HTTP.Do(req)
		if err != nil {
			ultimo = err
			continue
		}
		datos, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
		resp.Body.Close()
		if err != nil {
			ultimo = err
			continue
		}
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			ultimo = fmt.Errorf("respuesta %s", resp.Status)
			continue
		}
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("respuesta %s", resp.Status)
		}
		return json.Unmarshal(datos, destino)
	}
	return ultimo
}
