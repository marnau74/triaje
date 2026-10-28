# Proyecto de ejemplo

Dependencias **viejas a propósito**, con vulnerabilidades conocidas, para probar triaje:

```bash
go run ./cmd/triaje ejemplo
```

- `servicio/go.mod`: `golang.org/x/net` 0.7.0, afectado por HTTP/2 Rapid Reset (CVE-2023-44487), que está en el catálogo KEV.
- `api/requirements.txt`: Django 3.2.0, PyYAML 5.3.1 y requests 2.25.1. `Jinja2>=3.0` no está fijada y se ignora.
- `web/package-lock.json`: lodash 4.17.4, minimist 1.2.0, axios 0.21.0 y una copia anidada de qs.

No es código que se ejecute: solo están los ficheros de dependencias.
