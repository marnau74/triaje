package fuentes

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// Cache guarda respuestas en ficheros JSON dentro de una carpeta.
type Cache struct {
	Carpeta string
}

// CacheDelUsuario usa la carpeta de caché del sistema (%LocalAppData% en
// Windows, ~/.cache en Linux, ~/Library/Caches en macOS).
func CacheDelUsuario() *Cache {
	base, err := os.UserCacheDir()
	if err != nil {
		return nil
	}
	return &Cache{Carpeta: filepath.Join(base, "triaje")}
}

// Leer rellena destino si el fichero existe y no es más antiguo que vigencia
// (0 = sirve aunque esté caducado).
func (c *Cache) Leer(nombre string, vigencia time.Duration, destino any) bool {
	ruta := filepath.Join(c.Carpeta, nombre)
	info, err := os.Stat(ruta)
	if err != nil || (vigencia > 0 && time.Since(info.ModTime()) > vigencia) {
		return false
	}
	datos, err := os.ReadFile(ruta)
	if err != nil {
		return false
	}
	return json.Unmarshal(datos, destino) == nil
}

// Guardar escribe en un fichero temporal y lo renombra, para que una
// ejecución que se corte a medias no deje la caché rota. Un fallo al guardar
// no es grave: la próxima vez se vuelve a descargar.
func (c *Cache) Guardar(nombre string, valor any) {
	if err := os.MkdirAll(c.Carpeta, 0o755); err != nil {
		return
	}
	datos, err := json.Marshal(valor)
	if err != nil {
		return
	}
	tmp, err := os.CreateTemp(c.Carpeta, nombre+".*.tmp")
	if err != nil {
		return
	}
	_, errEsc := tmp.Write(datos)
	errCer := tmp.Close()
	if errEsc != nil || errCer != nil {
		os.Remove(tmp.Name())
		return
	}
	if err := os.Rename(tmp.Name(), filepath.Join(c.Carpeta, nombre)); err != nil {
		os.Remove(tmp.Name())
	}
}
