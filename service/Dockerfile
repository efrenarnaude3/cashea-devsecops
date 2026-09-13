# syntax=docker/dockerfile:1.6
#
# Multi-stage, distroless, non-root.
#
# Tres detalles que son la diferencia entre una imagen que corre y una que
# falla recién en el arranque del contenedor:
#
# 1. La versión de Node del build y la del runtime tienen que ser la misma
#    familia. El runtime es `gcr.io/distroless/nodejs20-debian12`, así que el
#    build es node:20. Con node:22 compilando para un runtime 20, cualquier
#    dependencia con binding nativo revienta al importar.
# 2. Las dependencias de producción se instalan en su propio stage con
#    `npm ci --omit=dev`, y el stage de build instala todo. Así el runtime
#    recibe node_modules sin devDependencies: menos superficie y menos CVEs
#    que triagear que no son de producción.
# 3. La imagen distroless ya trae ENTRYPOINT apuntando a node, así que CMD
#    lleva solo la ruta del script.
#
# `npm ci` exige package-lock.json. Si todavía no existe, generalo con
# `npm install --package-lock-only` y commitealo: es el pin real de las
# dependencias transitivas, y sin él el build no es reproducible.

FROM node:20-bookworm-slim AS deps
WORKDIR /app
ENV NPM_CONFIG_FUND=false NPM_CONFIG_AUDIT=false
COPY package.json package-lock.json ./
RUN npm ci --omit=dev

FROM node:20-bookworm-slim AS build
WORKDIR /app
ENV NPM_CONFIG_FUND=false NPM_CONFIG_AUDIT=false
COPY package.json package-lock.json ./
RUN npm ci
COPY tsconfig.json nest-cli.json ./
COPY src ./src
RUN npm run build

FROM gcr.io/distroless/nodejs20-debian12:nonroot
WORKDIR /app

ENV NODE_ENV=production \
    PORT=8080

COPY --from=deps --chown=nonroot:nonroot /app/node_modules ./node_modules
COPY --from=build --chown=nonroot:nonroot /app/dist ./dist
COPY --chown=nonroot:nonroot package.json ./

EXPOSE 8080
USER nonroot

# Sin HEALTHCHECK a propósito: distroless no tiene shell ni curl, así que no
# hay forma portable de expresarlo acá. El destino es Cloud Run y Kubernetes,
# donde el health check se declara como probe HTTP contra /health y
# /health/ready (ver deploy/k8s/deployment.yaml), que es lo que realmente
# controla el tráfico y los reinicios.

CMD ["dist/main.js"]
