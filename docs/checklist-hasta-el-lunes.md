# Qué hacer, en orden, hasta el lunes

Cinco bloques. Los dos primeros son de hoy y no dependen de nada externo. El
tercero necesita GitHub. El cuarto necesita Docker. El quinto es el ensayo.

Tiempo total: entre dos y tres horas, repartibles.

---

## Bloque 0 — Herramientas (20 minutos, una sola vez)

PowerShell **como administrador**:

```powershell
winget install OpenJS.NodeJS.LTS
winget install Python.Python.3.12
winget install Docker.DockerDesktop
winget install Kubernetes.kind
winget install Kubernetes.kubectl
```

Cerrá y reabrí PowerShell para que el PATH se actualice. Verificá:

```powershell
node --version      # v20.x o v22.x
python --version    # 3.11+
docker --version
kind --version
kubectl version --client
```

Si `python` no responde pero `py` sí, usá `py` en todos los comandos de abajo.

Docker Desktop tiene que quedar **corriendo** (ícono en la barra de tareas).
En el primer arranque pide reiniciar y habilitar WSL2: hacelo ahora, no el
domingo a la noche.

---

## Bloque 1 — Mover el repo y verificarlo offline (15 minutos)

### 1.1 Mover a una ruta corta

La carpeta de sesión de Cowork tiene 180 caracteres y ya te rompió `git add`
una vez. Empezá por sacarlo de ahí.

```powershell
$origen = "C:\Users\efrenarnaude\AppData\Roaming\Claude\local-agent-mode-sessions\ea61f4be-5f59-4a61-9e30-7ca60a598567\a33d630e-7587-4c3b-bb28-810c38cf956d\local_22f51f6e-ae68-4bbc-99b1-b12ea9842c52\outputs\heimdall"
$destino = "C:\dev\heimdall"

New-Item -ItemType Directory -Force -Path $destino | Out-Null
robocopy $origen $destino /E | Out-Null
cd $destino
```

### 1.2 Generar el lockfile

Es lo único que yo no pude generar. Sin esto no corre CI ni el `docker build`.

```powershell
cd service
npm install --package-lock-only
cd ..
```

Tarda un minuto y necesita red. Confirmá que exista `service\package-lock.json`.

### 1.3 Primera ejecución real del código

```powershell
.\demo.ps1 check
```

Si PowerShell bloquea el script:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

**Esperado:** 9 chequeos, todos en PASS (el aviso del lockfile ya no debería
aparecer porque lo generaste en 1.2), y después el self-test del gate con
`12/12 casos pasaron`.

**Si algo falla:** copiá la salida completa y pasámela. Es la primera vez que
este código se ejecuta.

### 1.4 Ver al gate decidir

```powershell
.\demo.ps1 gate
```

**Esperado:** exit 1, bloqueado por `CVE-2026-1000`, y los otros cuatro
hallazgos pasando cada uno por un motivo distinto. El reporte completo queda en
`gate-report.md`.

Leé esa tabla con calma: es lo que vas a explicar el lunes.

---

## Bloque 2 — Ensayar el bypass (10 minutos)

Practicá las dos ediciones que hacés en vivo. Abrí `appsec\exceptions.yaml` y
agregá, debajo de la excepción que ya está:

```yaml
  - id: CVE-2026-1000
    reason: >-
      El paquete afectado no se invoca desde ningún endpoint expuesto.
      Verificado contra el SBOM de la imagen.
    approved_by: efren
    expires_on: 2026-10-15
```

```powershell
.\demo.ps1 gate      # ahora tiene que pasar: exit 0
```

Cambiá `expires_on` a `2026-09-01` (una fecha pasada):

```powershell
.\demo.ps1 gate      # vuelve a bloquear, solo
```

Sacá `approved_by` por completo:

```powershell
.\demo.ps1 gate      # exit 2: error de configuración, no "todo bien"
```

Dejá el archivo como estaba al principio (sin la excepción de CVE-2026-1000):
ese es el estado con el que arrancás el demo.

---

## Bloque 3 — GitHub (30 minutos)

### 3.1 Git local

```powershell
cd C:\dev\heimdall
git init -b main
git add .
git status
```

Revisá la lista antes de commitear. **No tienen que aparecer** `.env`,
`*.tfstate`, `*.tfvars` ni `node_modules`. **Sí tiene que aparecer**
`demo/findings/trivy-image.json`, que es el archivo del demo:

```powershell
git check-ignore -v demo\findings\trivy-image.json
```

Si ese comando devuelve algo, el archivo está ignorado y hay que arreglarlo
antes de seguir. Si no devuelve nada, está bien.

```powershell
git commit -m "Heimdall: gate de CD con firma de imagen y control de admision"
```

### 3.2 Crear el repositorio en GitHub

Crealo **público** y **vacío** (sin README, sin licencia, sin .gitignore).

Público importa por tres razones concretas:

- CodeQL y secret scanning son gratis en repos públicos.
- Los minutos de GitHub Actions son ilimitados en repos públicos.
- La imagen en ghcr.io tiene que ser accesible sin credenciales para que el
  clúster local la pueda bajar.

```powershell
git remote add origin https://github.com/TU-USUARIO/heimdall.git
git push -u origin main
```

### 3.3 Primera corrida: en modo preview

**Antes de pushear**, abrí `appsec\gate.yaml` y poné:

```yaml
mode: preview
```

Esto no es una concesión: es el método que el propio proyecto propone. Nadie
enciende enforce sin haber medido antes qué habría bloqueado. Y evita que la
primera corrida se ponga roja por un CVE nuevo de Debian que no controlás.

```powershell
git add appsec\gate.yaml
git commit -m "Arranca en preview, como manda el proceso de adopcion"
git push
```

Andá a la pestaña Actions y mirá la corrida. **Esperado:** todo verde, y en el
resumen del job del gate la tabla diciendo qué *habría* bloqueado.

Ese número es oro para el lunes: es exactamente el dato que le vas a pedir a J
para el piloto.

### 3.4 Hacer pública la imagen

Cuando la corrida termine, andá a tu perfil de GitHub → Packages →
`heimdall-notes-api` → Package settings → Change visibility → **Public**.

Si te saltás este paso, el clúster local no va a poder bajar la imagen y el
paso 4 del demo falla.

### 3.5 Volver a enforce

```powershell
# en appsec\gate.yaml: mode: enforce
git add appsec\gate.yaml
git commit -m "Enforce, ya con el dato de preview a la vista"
git push
```

Si esta corrida se pone roja por un CVE real del sistema base, tenés dos
opciones y las dos son defendibles: agregar la excepción con justificación (y
mostrarla el lunes como caso real, que es aún mejor que el sintético), o
volver a preview y explicar por qué.

---

## Bloque 4 — El clúster (30 minutos, hacelo el domingo)

Con Docker Desktop corriendo:

```powershell
cd C:\dev\heimdall
.\demo.ps1 up -Owner TU-USUARIO
```

Tarda entre tres y cinco minutos: baja la imagen de kind, crea el clúster e
instala Kyverno. Si falla por timeout, corré el mismo comando de nuevo.

```powershell
.\demo.ps1 policy -Owner TU-USUARIO
.\demo.ps1 deny
```

**Esperado:** el Pod es rechazado y se ve el mensaje de la política.

```powershell
.\demo.ps1 deploy -Owner TU-USUARIO
curl http://localhost:8080/health
```

**Esperado:** el Pod es admitido y el health responde `{"status":"ok"}`.

Si `deploy` es rechazado, casi siempre es una de dos: la imagen todavía no está
firmada (mirá que la corrida de Actions haya llegado al paso de cosign), o el
paquete de ghcr sigue privado (paso 3.4).

**Dejá el clúster levantado.** Borrarlo y recrearlo el lunes es tiempo que no
tenés.

---

## Bloque 5 — Ensayo y preparación (40 minutos)

### 5.1 Cachear el provider de Terraform

```powershell
terraform -chdir=terraform init -backend=false
```

No necesita credenciales, pero sí red. Hacelo ahora para que el paso 5 del
demo no dependa del wifi de la reunión.

### 5.2 Ensayo completo con cronómetro

Corré `docs\demo-runbook.md` de principio a fin, en voz alta, midiendo. Si te
pasás de doce minutos, sacá el paso 5 (el de Terraform) y dejalo como respuesta
a una pregunta en vez de como parte del guion.

### 5.3 Releer el guion de la reunión

`GUION-reunion-lunes.md`: los primeros dos minutos, las cinco preguntas para J,
y sobre todo la lista de qué **no** decir. El error más caro sería presentar
esto como si los gates no tuvieran dueño: la épica es de Pato y vos entrás por
la parte que está en cero.

### 5.4 Dejar preparado

- Pestaña 1: la terminal en `C:\dev\heimdall`.
- Pestaña 2: `appsec\exceptions.yaml` abierto, con el bloque de la excepción
  listo para pegar.
- Pestaña 3: el repo en GitHub, en la corrida verde de Actions.
- Pestaña 4: la slide de R-005.
- Pestaña 5: `docs\plan.md`.

---

## El lunes, 30 minutos antes

```powershell
docker ps                       # Docker Desktop arriba
kubectl get nodes               # el clúster responde
kubectl get clusterpolicies     # la política está activa
.\demo.ps1 check                # todo en verde
```

Si el clúster no responde: `.\demo.ps1 up -Owner TU-USUARIO` de nuevo, y
mientras tanto arrancá el demo por los bloques que no lo necesitan (el gate y
el Terraform son el 70% del contenido).

---

## Si algo se cae en vivo

**El clúster no levanta.** Pasos 1, 2 y 5 del runbook no necesitan Docker.

**La imagen no está firmada.** Decilo antes de que lo vean: "acá el control me
está frenando a mí, que es exactamente para lo que está". Y mostrá `deny`, que
no depende de la firma.

**Actions está roja.** Abrí el reporte del gate igual: una corrida bloqueada
demuestra el control mejor que una verde.

**Nada funciona.** Quedan el plan, el mapeo a las cuatro celdas de R-005 y las
cinco preguntas. El proyecto se sostiene sin el demo; el demo es la evidencia,
no el argumento.
