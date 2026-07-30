# PostgreSQL Kurulumu

```bash
docker compose up -d      # postgres:16-alpine, host portu 5434
yarn prisma:migrate
yarn start:dev
```

- `schema.prisma` değişirse → `yarn prisma:migrate`
- TS tip hatası veriyorsa → `yarn prisma:generate`
- Prod deploy → `yarn prisma:migrate:deploy`

Ayrıntılı kurulum, ortam değişkenleri, seed ve sorun giderme için:
[`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md)
