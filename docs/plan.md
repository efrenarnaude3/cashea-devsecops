# Heimdall — plan del proyecto

Aporte a la épica **Pipeline seguro (CASHE2-1266)**, no un proyecto paralelo.
Ataca las dos filas de esa épica que hoy están en cero.

> **Objetivo.** Que un deploy que no pasó por el pipeline no llegue a correr, y
> que todo bypass del control quede con justificación, aprobador y fecha de
> vencimiento.

## Qué mueve

Cuatro celdas de la fila de Pipeline seguro en el mapa de riesgo R-005, medidas
contra su objetivo de Q3:

| Métrica | Hoy | Q3 esperado | Qué hace este proyecto |
|---|---|---|---|
| Deploys escaneados | 0% (0 de TBD) | 100% | Primero resuelve el TBD y después escanea: sin denominador no hay porcentaje que reportar |
| Deploys bloqueados | 0 de 0 | — | Binary Authorization en enforce: el primer deploy rechazado es la evidencia de que el control existe |
| ByPass sin justificación | 8 de 2221 | 0% | Excepción as-code con aprobador y vencimiento: sin los cuatro campos no hay bypass posible |
| Vulnerabilidades fuera de SLA | 43% (46 de 107) | 0% | Indirecto: el gate corta el ingreso de hallazgos nuevos mientras el backlog se drena |

El lado de PR de esa misma épica ya tiene mecanismo andando (74,2% de PRs
escaneados, 15 bloqueados). Este proyecto entra por CD, que es la parte en cero.

## Qué entra y qué no

**Entra.** El control en tiempo de deploy: imagen escaneada y firmada por el
pipeline, attestation, y admisión en enforce. El inventario de deploys que hoy
es TBD. Las excepciones con aprobador y vencimiento. El panel con las cuatro
métricas.

**No entra.** El escaneo en PR, que ya funciona. Crear hallazgos o tickets, que
son de GHAS, Fluid y VULNMGMT. Notificaciones por vertical, que son de Valhalla.
Inventario de superficie de API, que es de Horus. El escaneo mensual de los 46
repos, que es de Mythos-Scan. WAF y Cloudflare, que son de CASHE2-1278. Bajar
umbrales o cambiar SLA. Mobile queda para v4.

## Sprints

| Sprint | Fechas | Entregable | Checkpoint |
|---|---|---|---|
| 0 | 12–14 sep | Implementación de referencia completa: gate con delta gating y excepciones, pipeline que firma, control de admisión rechazando lo no firmado | Demo en vivo; `check` en verde y self-test del gate en 11/11 |
| 1 | 15–29 sep | El denominador: inventario de deploys a Cloud Run, cuáles salen de CI y cuáles no. Servicio piloto elegido | "0 de TBD" pasa a "0 de N", con N escrito y su fuente |
| 2 | 30 sep – 14 oct | El piloto escanea y firma en CI. Política y attestor en Terraform, en dryrun | El piloto reporta 100% de sus deploys escaneados; un deploy sin firmar queda en el audit log sin bloquear |
| 3 | 15–29 oct | Binary Authorization en enforce en el proyecto del piloto. **Cierra v1** | Un deploy sin attestation es rechazado; la métrica de bloqueados tiene numerador |
| 4 | 30 oct – 13 nov | Excepciones as-code para PR y deploy. Panel con las cuatro métricas. **Cierra v2** | Un bypass sin los cuatro campos no compila; una excepción vencida vuelve a bloquear sola |
| 5 | 14–28 nov | Adopción por vertical en el orden de los 46 repos T1. Runbook y handoff. **Cierra v3** | Otra persona del equipo adopta un servicio y lo lleva a enforce sin el autor del proyecto |

## Riesgos

| Riesgo | Impacto | Mitigación |
|---|---|---|
| Deploys que hoy salen fuera de CI. Si existen, encender el control los rompe el primer día | Alto | El sprint 1 es el inventario, antes de tocar nada. El sprint 2 corre en dryrun: registra sin bloquear |
| El muro de legacy: bloquear hallazgos previos frena todos los merges y el squad pide apagar el control | Alto | Delta gating por fecha de adopción. El backlog lo drena el proceso de vulnerabilidades con su SLA |
| Pisar la épica de Pato, que ya tiene el lado de PR andando | Alto | El proyecto entra por CD y se reporta dentro de CASHE2-1266 |
| Otro pipeline revirtiendo configuración, como ya pasó dos veces con los attaches de policy de Cloud Armor | Medio | La política vive en el repo de IaC de seguridad, con su propio state. Verificar antes del sprint 3 |
| Que el control dependa de su autor | Medio | El sprint 5 es handoff y su checkpoint lo ejecuta otra persona |
| El monolito: es donde está el volumen y el peor lugar para empezar | Medio | El piloto es un servicio chico que ya despliega desde CI. El monolito entra después, en preview |

## Datos pendientes

1. ¿Cuántos deploys a Cloud Run hay por semana y cuáles no salen de CI?
2. ¿Dónde está encendido hoy el bloqueo en PR? El hub de AppSecurity y la ppt
   de cyber no dicen lo mismo.
3. ¿Los 8 bypasses sin justificación fueron en PR, en deploy, o en ambos?
4. ¿Alguien administra ya una política de Binary Authorization en los proyectos
   de GCP?
