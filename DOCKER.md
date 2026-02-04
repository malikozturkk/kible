# PostgreSQL Kurulumu

```bash
docker compose up -d
```
yarn prisma:migrate
```
yarn start:dev
```

## .env örneği

```
POSTGRES_USER=postgres
POSTGRES_PASSWORD=postgres
POSTGRES_DB=kible
POSTGRES_PORT=5432
DATABASE_URL="postgresql://postgres:postgres@localhost:5432/kible"
PORT=3000
NODE_ENV=development
```

Sonrasında: `yarn prisma:migrate`
