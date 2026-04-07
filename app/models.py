from pydantic import BaseModel, Field


class UserBase(BaseModel):
    username: str = Field(..., min_length=1)


class User(UserBase):
    password: str = Field(..., min_length=1)


class UserRegister(User):
    role: str = 'user'


class UserInDB(UserBase):
    hashed_password: str
    role: str = 'user'


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = 'bearer'


class TodoCreate(BaseModel):
    title: str
    description: str


class TodoUpdate(BaseModel):
    title: str
    description: str
    completed: bool


class TodoOut(BaseModel):
    id: int
    title: str
    description: str
    completed: bool
