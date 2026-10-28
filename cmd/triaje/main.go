// triaje busca las vulnerabilidades conocidas de las dependencias de un
// proyecto y las ordena por riesgo real: si se están explotando (KEV), si es
// probable que se exploten (EPSS) y lo graves que son (CVSS).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/marnau74/triaje/internal/analisis"
	"github.com/marnau74/triaje/internal/fuentes"
	"github.com/marnau74/triaje/internal/informe"
	"github.com/marnau74/triaje/internal/inventario"
	"github.com/marnau74/triaje/internal/riesgo"
)

// version la fija la compilación de las versiones publicadas:
// go build -ldflags "-X main.version=v1.0.0"
var version = "desarrollo"

// Códigos de salida, para usarlo en la CI.
const (
	salidaBien   = 0
	salidaUmbral = 1 // hay hallazgos de la prioridad pedida en -fallar-en o más urgentes
	salidaError  = 2 // error de uso, al leer los ficheros o al consultar las fuentes
)

func main() {
	ctx, parar := signal.NotifyContext(context.Background(), os.Interrupt)
	defer parar()
	os.Exit(ejecutar(ctx, os.Args[1:], os.Stdout, os.Stderr, fuentes.NuevoCliente()))
}

func ejecutar(ctx context.Context, args []string, salida, errores io.Writer, cliente *fuentes.Cliente) int {
	fs := flag.NewFlagSet("triaje", flag.ContinueOnError)
	fs.SetOutput(errores)
	formato := fs.String("formato", "tabla", "formato de salida: "+strings.Join(informe.Formatos, ", "))
	fichero := fs.String("salida", "", "fichero en el que escribir el informe (por defecto, la salida estándar)")
	fallarEn := fs.String("fallar-en", "", "termina con código 1 si hay hallazgos de esta prioridad o más urgentes: p1, p2, p3 o p4")
	solo := fs.String("solo", "", "muestra solo los hallazgos de esta prioridad o más urgentes: p1, p2, p3 o p4")
	sinCache := fs.Bool("sin-cache", false, "no usar ni guardar la copia local del catálogo KEV")
	verVersion := fs.Bool("version", false, "muestra la versión y termina")
	tiempo := fs.Duration("tiempo-maximo", 2*time.Minute, "tiempo máximo para consultar las fuentes")
	fs.Usage = func() {
		fmt.Fprintf(errores, "Uso: triaje [opciones] [ruta]\n\n"+
			"Analiza los ficheros de dependencias de la ruta (por defecto, la carpeta actual)\n"+
			"y ordena sus vulnerabilidades por prioridad: P1 se está explotando, P2 es probable\n"+
			"que se explote, P3 grave o con alguna probabilidad, P4 puede esperar.\n\n"+
			"Lee go.mod, package-lock.json, requirements*.txt, Cargo.lock, packages.lock.json\n"+
			"y SBOM CycloneDX en JSON (*.cdx.json, bom.json, sbom.json).\n\nOpciones:\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return salidaBien
		}
		return salidaError
	}
	if *verVersion {
		fmt.Fprintln(salida, "triaje", version)
		return salidaBien
	}
	if fs.NArg() > 1 {
		fmt.Fprintln(errores, "triaje: solo se puede analizar una ruta cada vez")
		return salidaError
	}
	ruta := "."
	if fs.NArg() == 1 {
		ruta = fs.Arg(0)
	}
	var umbral riesgo.Prioridad
	if *fallarEn != "" {
		u, err := riesgo.ParsePrioridad(*fallarEn)
		if err != nil {
			fmt.Fprintln(errores, "triaje:", err)
			return salidaError
		}
		umbral = u
	}
	var minima riesgo.Prioridad
	if *solo != "" {
		m, err := riesgo.ParsePrioridad(*solo)
		if err != nil {
			fmt.Fprintln(errores, "triaje:", err)
			return salidaError
		}
		minima = m
	}
	valido := false
	for _, f := range informe.Formatos {
		valido = valido || f == *formato
	}
	if !valido {
		fmt.Fprintf(errores, "triaje: formato desconocido %q (usa %s)\n", *formato, strings.Join(informe.Formatos, ", "))
		return salidaError
	}
	if !*sinCache && cliente.Cache == nil {
		cliente.Cache = fuentes.CacheDelUsuario()
	}

	paquetes, err := inventario.Leer(ruta)
	if err != nil {
		fmt.Fprintln(errores, "triaje:", err)
		return salidaError
	}
	ctx, cancelar := context.WithTimeout(ctx, *tiempo)
	defer cancelar()
	inf, err := analisis.Analizar(ctx, cliente, ruta, paquetes)
	if err != nil {
		fmt.Fprintln(errores, "triaje:", err)
		return salidaError
	}

	// -fallar-en mira todos los hallazgos, antes de quitar los que -solo no
	// quiere enseñar.
	superaUmbral := false
	for _, h := range inf.Hallazgos {
		superaUmbral = superaUmbral || (umbral != 0 && h.Prioridad <= umbral)
	}
	if minima != 0 {
		inf.Filtrar(minima)
	}

	if *fichero == "" {
		err = informe.Escribir(salida, *formato, inf, version)
	} else {
		err = escribirFichero(*fichero, *formato, inf)
	}
	if err != nil {
		fmt.Fprintln(errores, "triaje:", err)
		return salidaError
	}
	if *fichero != "" {
		// Con el informe en un fichero, un resumen en la terminal sigue siendo útil.
		fmt.Fprintf(errores, "Informe guardado en %s: P1 %d · P2 %d · P3 %d · P4 %d\n", *fichero,
			inf.Resumen["P1"], inf.Resumen["P2"], inf.Resumen["P3"], inf.Resumen["P4"])
	}

	if superaUmbral {
		fmt.Fprintf(errores, "triaje: hay vulnerabilidades de prioridad %s o más urgentes\n", umbral)
		return salidaUmbral
	}
	return salidaBien
}

func escribirFichero(ruta, formato string, inf *analisis.Informe) error {
	f, err := os.Create(ruta)
	if err != nil {
		return err
	}
	if err := informe.Escribir(f, formato, inf, version); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
