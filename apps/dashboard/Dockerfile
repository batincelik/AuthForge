FROM node:24-alpine AS build
WORKDIR /app
ARG NEXT_PUBLIC_AUTHFORGE_API_URL=http://localhost:8000
ENV NEXT_PUBLIC_AUTHFORGE_API_URL=$NEXT_PUBLIC_AUTHFORGE_API_URL
COPY apps/dashboard/package*.json ./
RUN npm install
COPY apps/dashboard ./
RUN npm run build
FROM node:24-alpine
WORKDIR /app
COPY --from=build /app/.next/standalone ./
COPY --from=build /app/.next/static ./.next/static
EXPOSE 3000
CMD ["node", "server.js"]
