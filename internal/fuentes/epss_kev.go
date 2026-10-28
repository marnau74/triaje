package fuentes

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// EPSS es la probabilidad (0-1) de que una CVE se explote en los próximos 30
// días según el modelo de FIRST, y el percentil que ocupa entre todas.
type EPSS struct {
	Probabilidad float64 `json:"probabilidad"`
	Percentil    float64 `json:"percentil"`
	Fecha        string  `json:"fecha"`
}

// la API de FIRST admite hasta 100 CVE por petición.
const loteEPSS = 100

func (c *Cliente) BuscarEPSS(ctx context.Context, cves []string) (map[string]EPSS, error) {
	res := map[string]EPSS{}
	for ini := 0; ini < len(cves); ini += loteEPSS {
		fin := min(ini+loteEPSS, len(cves))
		var resp struct {
			Data []struct {
				CVE        string `json:"cve"`
				EPSS       string `json:"epss"`
				Percentile string `json:"percentile"`
				Date       string `json:"date"`
			} `json:"data"`
		}
		dir := c.EPSSURL + "?cve=" + url.QueryEscape(strings.Join(cves[ini:fin], ","))
		if err := c.getJSON(ctx, dir, &resp); err != nil {
			return nil, fmt.Errorf("EPSS: %w", err)
		}
		for _, d := range resp.Data {
			p, err1 := strconv.ParseFloat(d.EPSS, 64)
			pc, err2 := strconv.ParseFloat(d.Percentile, 64)
			if err1 != nil || err2 != nil {
				continue
			}
			res[d.CVE] = EPSS{Probabilidad: p, Percentil: pc, Fecha: d.Date}
		}
	}
	return res, nil
}

// EntradaKEV es una vulnerabilidad del catálogo de CISA.
type EntradaKEV struct {
	CVE             string `json:"cve"`
	Nombre          string `json:"nombre"`
	FechaAlta       string `json:"fecha_alta"`
	FechaLimite     string `json:"fecha_limite"` // plazo que CISA da a las agencias federales
	Ransomware      bool   `json:"ransomware"`   // usada en campañas de ransomware conocidas
	AccionRequerida string `json:"accion_requerida"`
}

// El catálogo entero ocupa poco más de 1 MB y cambia unas pocas veces por
// semana, así que se descarga entero y se guarda un día en caché.
const vigenciaKEV = 24 * time.Hour

func (c *Cliente) CatalogoKEV(ctx context.Context) (map[string]EntradaKEV, error) {
	var resp struct {
		Vulnerabilities []struct {
			CVEID                      string `json:"cveID"`
			VulnerabilityName          string `json:"vulnerabilityName"`
			DateAdded                  string `json:"dateAdded"`
			DueDate                    string `json:"dueDate"`
			RequiredAction             string `json:"requiredAction"`
			KnownRansomwareCampaignUse string `json:"knownRansomwareCampaignUse"`
		} `json:"vulnerabilities"`
	}
	ok := c.Cache != nil && c.Cache.Leer("kev.json", vigenciaKEV, &resp)
	if !ok {
		if err := c.getJSON(ctx, c.KEVURL, &resp); err != nil {
			// Sin red, mejor una copia vieja que nada.
			if c.Cache != nil && c.Cache.Leer("kev.json", 0, &resp) {
				ok = true
			} else {
				return nil, fmt.Errorf("KEV: %w", err)
			}
		}
		if !ok && c.Cache != nil {
			c.Cache.Guardar("kev.json", resp)
		}
	}
	res := make(map[string]EntradaKEV, len(resp.Vulnerabilities))
	for _, v := range resp.Vulnerabilities {
		res[v.CVEID] = EntradaKEV{
			CVE:             v.CVEID,
			Nombre:          v.VulnerabilityName,
			FechaAlta:       v.DateAdded,
			FechaLimite:     v.DueDate,
			Ransomware:      strings.EqualFold(v.KnownRansomwareCampaignUse, "Known"),
			AccionRequerida: v.RequiredAction,
		}
	}
	return res, nil
}
