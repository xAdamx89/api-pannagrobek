import os
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Optional

import bcrypt
import jwt
from fastapi import FastAPI, Depends, HTTPException, status, Body
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from sqlalchemy import text
from pydantic import BaseModel
from database import get_db

# --- Konfiguracja JWT ---
# Na produkcji koniecznie ustaw długi ciąg znaków w zmiennej środowiskowej JWT_SECRET_KEY!
SECRET_KEY = os.getenv("JWT_SECRET_KEY", "zmien-mnie-na-produkcji-super-tajny-klucz-2137")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24  # Token ważny przez 24 godziny

# Wskazuje FastAPI (oraz dokumentacji Swagger /docs), gdzie znajduje się endpoint logowania
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")

# Brak globalnego dependencies=[...], aby endpoint /token był publicznie dostępny
app = FastAPI()


# --- Modele Pydantic ---
class Token(BaseModel):
    access_token: str
    token_type: str


class CurrentUser(BaseModel):
    user_id: int
    tenant_id: int
    login: str


class UpdatePayload(BaseModel):
    pk_column: str
    pk_value: Any
    data: Dict[str, Any]


# --- Funkcje pomocnicze (Bcrypt & JWT) ---
def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Weryfikuje hasło tekstowe z hashem bcrypt z bazy."""
    plain_bytes = plain_password.encode('utf-8')
    hashed_bytes = hashed_password.encode('utf-8')
    return bcrypt.checkpw(plain_bytes, hashed_bytes)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Generuje podpisany token JWT."""
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def get_current_user(token: str = Depends(oauth2_scheme)) -> CurrentUser:
    """Zależność (Dependency) weryfikująca token JWT przy każdym zapytaniu."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Nie można zweryfikować poświadczeń (błędny lub wygasły token)",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        tenant_id: int = payload.get("tenant_id")
        login: str = payload.get("login")
        
        if user_id is None or tenant_id is None:
            raise credentials_exception
            
        return CurrentUser(user_id=int(user_id), tenant_id=tenant_id, login=login)
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token wygasł. Zaloguj się ponownie.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.InvalidTokenError:
        raise credentials_exception


# --- Funkcje weryfikujące bezpieczeństwo SQL ---
def validate_identifier(name: str):
    if not name.isidentifier():
        raise HTTPException(status_code=400, detail=f"Nieprawidłowa nazwa tabeli lub kolumny: {name}")


# --- Endpoint Autoryzacyjny ---
@app.post("/token", response_model=Token)
def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(), 
    db: Session = Depends(get_db)
):
    # Wyszukujemy użytkownika po loginie lub emailu
    query = text("""
        SELECT user_id, tenant_id, login, email, hashed_password, nw_status 
        FROM uzytkownicy 
        WHERE login = :username OR email = :username
        LIMIT 1
    """)
    user = db.execute(query, {"username": form_data.username}).mappings().first()

    # Weryfikacja czy użytkownik istnieje i czy hasło się zgadza
    if not user or not verify_password(form_data.password, user["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Nieprawidłowy login lub hasło",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Opcjonalna blokada kont nieaktywnych (jeśli używasz kolumny nw_status np. 'BLOCKED' / 'INACTIVE')
    if user["nw_status"] == "INACTIVE":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Konto użytkownika jest nieaktywne",
        )

    # Pakujemy user_id oraz tenant_id bezpośrednio do payloadu tokena JWT
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={
            "sub": str(user["user_id"]),
            "tenant_id": user["tenant_id"],
            "login": user["login"] or user["email"]
        },
        expires_delta=access_token_expires
    )
    
    return {"access_token": access_token, "token_type": "bearer"}


# --- Zabezpieczone Endpointy API ---
@app.get("/api/select/{table}")
def generic_select(
    table: str, 
    where_col: Optional[str] = None, 
    where_val: Optional[str] = None, 
    db: Session = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user)
):
    validate_identifier(table)
    
    query_str = f"SELECT * FROM {table}"
    params = {}
    
    if where_col and where_val is not None:
        validate_identifier(where_col)
        query_str += f" WHERE {where_col} = :where_val"
        params["where_val"] = where_val
        
    try:
        result = db.execute(text(query_str), params).mappings().all()
        return [dict(row) for row in result]
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/insert/{table}")
def generic_insert(
    table: str, 
    payload: Dict[str, Any] = Body(...), 
    db: Session = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user)
):
    validate_identifier(table)
    
    if not payload:
        raise HTTPException(status_code=400, detail="Brak danych do wstawienia.")
        
    columns = list(payload.keys())
    for col in columns:
        validate_identifier(col)
        
    cols_str = ", ".join(columns)
    vals_str = ", ".join([f":{col}" for col in columns])
    
    query_str = f"INSERT INTO {table} ({cols_str}) VALUES ({vals_str}) RETURNING *"
    
    try:
        result = db.execute(text(query_str), payload).mappings().first()
        db.commit()
        return dict(result) if result else {"status": "success"}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(e))


@app.put("/api/update/{table}")
def generic_update(
    table: str, 
    payload: Dict[str, Any] = Body(...), 
    db: Session = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user)
):
    validate_identifier(table)
    
    if not payload:
        raise HTTPException(status_code=400, detail="Brak danych do aktualizacji.")

    pk = payload.pop("pk_column", None)
    if not pk:
        raise HTTPException(status_code=400, detail="W body brakuje klucza 'pk_column' określającego nazwę ID.")
        
    validate_identifier(pk)
    
    pk_val = payload.get(pk)
    if pk_val is None:
        raise HTTPException(status_code=400, detail=f"Brak wartości dla klucza '{pk}' w danych wejściowych.")

    set_clauses = []
    params = {}
    
    for col, val in payload.items():
        validate_identifier(col)
        if col != pk:
            set_clauses.append(f"{col} = :update_{col}")
            params[f"update_{col}"] = val

    if not set_clauses:
        raise HTTPException(status_code=400, detail="Brak pól do aktualizacji (oprócz klucza).")

    set_str = ", ".join(set_clauses)
    
    query_str = f"UPDATE {table} SET {set_str} WHERE {pk} = :pk_val RETURNING *"
    params["pk_val"] = pk_val
    
    try:
        result = db.execute(text(query_str), params).mappings().first()
        db.commit()
        if not result:
            raise HTTPException(status_code=404, detail="Nie znaleziono rekordu do aktualizacji.")
        return dict(result)
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/api/table_def/{tablica}")
def get_table_def(
    tablica: str, 
    db: Session = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user)
):
    sqlstmt = """
        SELECT 
            column_name, 
            data_type, 
            character_maximum_length,
            is_nullable
        FROM 
            information_schema.columns
        WHERE 
            table_name = :tablica
    """
    try:
        result = db.execute(text(sqlstmt), {"tablica": tablica}).mappings().all()
        return [dict(row) for row in result]
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))