# Build the console to static files, then serve them from nginx. The app is
# entirely client-side, so the runtime image needs no Node.
FROM node:22-alpine AS build
WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci

COPY . .
# Baked in at build time: a static export has no server to read env at runtime.
# Same-origin, so nginx proxies it to the backend and there is no CORS to think
# about.
ENV NEXT_PUBLIC_API_BASE=/api
RUN npm run build

FROM nginx:1.27-alpine
COPY --from=build /app/out /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
