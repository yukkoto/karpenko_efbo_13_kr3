# KR3 FastAPI Solution

Готовый проект под контрольную №3.

## Что покрыто
- 6.1/6.2 — Basic Auth + хеширование паролей + `WWW-Authenticate`
- 6.3 — документация скрыта в `PROD`, защищена в `DEV`
- 6.4/6.5 — JWT, `/protected_resource`, регистрация, rate limiting
- 7.1 — RBAC: `admin`, `user`, `guest`
- 8.1 — SQLite + raw SQL + регистрация
- 8.2 — CRUD для `Todo`

## Запуск
```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env
uvicorn app.main:app --reload
```

## Примеры curl

### Регистрация пользователя
```bash
curl -X POST http://127.0.0.1:8000/register \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"qwerty123","role":"admin"}'
```

### Basic Auth логин
```bash
curl -u alice:qwerty123 http://127.0.0.1:8000/login
```

### JWT логин
```bash
curl -X POST http://127.0.0.1:8000/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"qwerty123"}'
```

### Доступ к protected_resource
```bash
curl http://127.0.0.1:8000/protected_resource \
  -H "Authorization: Bearer <TOKEN>"
```

### Create Todo (admin)
```bash
curl -X POST http://127.0.0.1:8000/admin/todos \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"title":"Buy groceries","description":"Milk, eggs, bread"}'
```

### Read Todo
```bash
curl http://127.0.0.1:8000/todos/1 \
  -H "Authorization: Bearer <TOKEN>"
```

### Update Todo
```bash
curl -X PUT http://127.0.0.1:8000/todos/1 \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"title":"Buy groceries","description":"Milk, eggs, bread","completed":true}'
```

### Delete Todo (admin)
```bash
curl -X DELETE http://127.0.0.1:8000/todos/1 \
  -H "Authorization: Bearer <TOKEN>"
```

## Важно
`/register_plain` оставлен как отдельный минимальный маршрут под 8.1, где пароль сохраняется как есть, потому что именно это явно указано в условии этой задачи.
