import os
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.responses import JSONResponse

from .database import get_db_connection, init_db
from .models import TokenResponse, TodoCreate, TodoOut, TodoUpdate, User, UserInDB, UserRegister
from .security import (
    auth_user,
    create_access_token,
    get_password_hash,
    get_current_user,
    rate_limiter,
    require_permission,
    verify_docs_user,
    verify_password,
)

MODE = os.getenv('MODE', 'DEV').upper()
if MODE not in {'DEV', 'PROD'}:
    raise RuntimeError('MODE must be DEV or PROD')

app = FastAPI(
    title='KR3 FastAPI Solution',
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)


@app.on_event('startup')
def startup() -> None:
    init_db()


@app.get('/')
def root() -> dict[str, str]:
    return {'message': f'Application is running in {MODE} mode'}


@app.post('/register', status_code=status.HTTP_201_CREATED)
@rate_limiter.limit('register', times=1, seconds=60)
async def register(request: Request, user: UserRegister) -> dict[str, str]:
    conn = get_db_connection()
    existing = conn.execute('SELECT username FROM users').fetchall()
    for row in existing:
        if row['username'] == user.username:
            conn.close()
            raise HTTPException(status_code=409, detail='User already exists')

    hashed_password = get_password_hash(user.password)
    user_in_db = UserInDB(
        username=user.username,
        hashed_password=hashed_password,
        role=user.role,
    )
    conn.execute(
        'INSERT INTO users (username, password, role) VALUES (?, ?, ?)',
        (user_in_db.username, user_in_db.hashed_password, user_in_db.role),
    )
    conn.commit()
    conn.close()
    return {'message': 'New user created'}


@app.get('/login')
def login_basic(current_user: dict[str, Any] = Depends(auth_user)) -> dict[str, str]:
    return {'message': f'Welcome, {current_user["username"]}!'}


@app.post('/login', response_model=TokenResponse)
@rate_limiter.limit('login', times=5, seconds=60)
async def login_jwt(request: Request, user: User):
    conn = get_db_connection()
    rows = conn.execute('SELECT username, password, role FROM users').fetchall()
    conn.close()

    found_user = None
    for row in rows:
        import secrets
        if secrets.compare_digest(row['username'], user.username):
            found_user = row
            break

    if not found_user:
        raise HTTPException(status_code=404, detail='User not found')

    if not verify_password(user.password, found_user['password']):
        raise HTTPException(status_code=401, detail='Authorization failed')

    token = create_access_token(found_user['username'], found_user['role'])
    return {'access_token': token, 'token_type': 'bearer'}


@app.get('/protected_resource')
def protected_resource(current_user=Depends(require_permission('read'))):
    return {'message': 'Access granted', 'user': current_user['username'], 'role': current_user['role']}


@app.post('/admin/todos', response_model=TodoOut)
def create_todo(todo: TodoCreate, current_user=Depends(require_permission('create'))):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        'INSERT INTO todos (title, description, completed, owner_username) VALUES (?, ?, ?, ?)',
        (todo.title, todo.description, 0, current_user['username']),
    )
    todo_id = cur.lastrowid
    conn.commit()
    row = conn.execute('SELECT id, title, description, completed FROM todos WHERE id = ?', (todo_id,)).fetchone()
    conn.close()
    return TodoOut(id=row['id'], title=row['title'], description=row['description'], completed=bool(row['completed']))


@app.get('/todos/{todo_id}', response_model=TodoOut)
def get_todo(todo_id: int, current_user=Depends(require_permission('read'))):
    conn = get_db_connection()
    row = conn.execute('SELECT id, title, description, completed FROM todos WHERE id = ?', (todo_id,)).fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail='Todo not found')
    return TodoOut(id=row['id'], title=row['title'], description=row['description'], completed=bool(row['completed']))


@app.put('/todos/{todo_id}', response_model=TodoOut)
def update_todo(todo_id: int, todo: TodoUpdate, current_user=Depends(require_permission('update'))):
    conn = get_db_connection()
    row = conn.execute('SELECT id FROM todos WHERE id = ?', (todo_id,)).fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail='Todo not found')
    conn.execute(
        'UPDATE todos SET title = ?, description = ?, completed = ? WHERE id = ?',
        (todo.title, todo.description, int(todo.completed), todo_id),
    )
    conn.commit()
    updated = conn.execute('SELECT id, title, description, completed FROM todos WHERE id = ?', (todo_id,)).fetchone()
    conn.close()
    return TodoOut(id=updated['id'], title=updated['title'], description=updated['description'], completed=bool(updated['completed']))


@app.delete('/todos/{todo_id}')
def delete_todo(todo_id: int, current_user=Depends(require_permission('delete'))):
    conn = get_db_connection()
    row = conn.execute('SELECT id FROM todos WHERE id = ?', (todo_id,)).fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail='Todo not found')
    conn.execute('DELETE FROM todos WHERE id = ?', (todo_id,))
    conn.commit()
    conn.close()
    return {'message': 'Todo deleted successfully'}


# 8.1 raw SQLite minimal endpoint preserved separately for the task statement
@app.post('/register_plain')
def register_plain(user: User):
    conn = get_db_connection()
    conn.execute(
        'INSERT INTO users (username, password, role) VALUES (?, ?, ?)',
        (user.username, user.password, 'user'),
    )
    conn.commit()
    conn.close()
    return {'message': 'User registered successfully!'}


@app.get('/docs', include_in_schema=False)
def custom_docs(_: str = Depends(verify_docs_user) if MODE == 'DEV' else None):
    if MODE == 'PROD':
        raise HTTPException(status_code=404, detail='Not Found')
    return get_swagger_ui_html(openapi_url='/openapi.json', title='docs')


@app.get('/openapi.json', include_in_schema=False)
def openapi_endpoint(_: str = Depends(verify_docs_user) if MODE == 'DEV' else None):
    if MODE == 'PROD':
        raise HTTPException(status_code=404, detail='Not Found')
    return JSONResponse(app.openapi())


@app.get('/redoc', include_in_schema=False)
def hidden_redoc():
    raise HTTPException(status_code=404, detail='Not Found')
