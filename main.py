import os
import secrets
from fastapi import FastAPI, Depends, HTTPException, Query, status, Body
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from sqlalchemy.orm import Session
from sqlalchemy import text
from pydantic import BaseModel
from typing import Dict, Any, Optional
from database import get_db

# --- Konfiguracja Autoryzacji ---
security = HTTPBasic()

def verify_credentials(credentials: HTTPBasicCredentials = Depends(security)):
    correct_user = secrets.compare_digest(credentials.username, os.getenv("API_USER", "admin"))
    correct_pass = secrets.compare_digest(credentials.password, os.getenv("API_PASS", "passwd"))
    
    if not (correct_user and correct_pass):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Nieprawidłowy login lub hasło",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username

app = FastAPI(dependencies=[Depends(verify_credentials)])

# --- Modele Pydantic ---
class UpdatePayload(BaseModel):
    pk_column: str
    pk_value: Any
    data: Dict[str, Any]

# --- Funkcje weryfikujące bezpieczeństwo ---
def validate_identifier(name: str):
    if not name.isidentifier():
        raise HTTPException(status_code=400, detail=f"Nieprawidłowa nazwa tabeli lub kolumny: {name}")

# --- Endpointy API ---
@app.get("/api/select/{table}")
def generic_select(
    table: str, 
    where_col: Optional[str] = None, 
    where_val: Optional[str] = None, 
    db: Session = Depends(get_db)
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
def generic_insert(table: str, payload: Dict[str, Any] = Body(...), db: Session = Depends(get_db)):
    validate_identifier(table)
    
    # POPRAWKA 1: payload to zwykły słownik, brak właściwości .data
    if not payload:
        raise HTTPException(status_code=400, detail="Brak danych do wstawienia.")
        
    columns = list(payload.keys())
    for col in columns:
        validate_identifier(col)
        
    cols_str = ", ".join(columns)
    vals_str = ", ".join([f":{col}" for col in columns])
    
    query_str = f"INSERT INTO {table} ({cols_str}) VALUES ({vals_str}) RETURNING *"
    
    try:
        # POPRAWKA 2: Użycie payload bezpośrednio jako parametrów zapytania
        result = db.execute(text(query_str), payload).mappings().first()
        db.commit()
        return dict(result) if result else {"status": "success"}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(e))

@app.put("/api/update/{table}")
def generic_update(table: str, payload: Dict[str, Any] = Body(...), db: Session = Depends(get_db)):
    validate_identifier(table)
    
    if not payload:
        raise HTTPException(status_code=400, detail="Brak danych do aktualizacji.")

    # 1. Pobieramy nazwę kolumny klucza z body (i od razu usuwamy z payloadu)
    pk = payload.pop("pk_column", None)
    if not pk:
        raise HTTPException(status_code=400, detail="W body brakuje klucza 'pk_column' określającego nazwę ID.")
        
    validate_identifier(pk)
    
    # 2. Wyciągnięcie wartości klucza głównego ze słownika
    pk_val = payload.get(pk)
    if pk_val is None:
        raise HTTPException(status_code=400, detail=f"Brak wartości dla klucza '{pk}' w danych wejściowych.")

    set_clauses = []
    params = {}
    
    for col, val in payload.items():
        validate_identifier(col)
        # Pomijamy aktualizację samego klucza głównego
        if col != pk:
            set_clauses.append(f"{col} = :update_{col}")
            params[f"update_{col}"] = val

    if not set_clauses:
        raise HTTPException(status_code=400, detail="Brak pól do aktualizacji (oprócz klucza).")

    set_str = ", ".join(set_clauses)
    
    # 3. Budowanie zapytania: UPDATE tabela SET col1 = :update_col1 WHERE nazwa_klucza = :pk_val
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

@app.get("/api/update/{tablica}")
def get_table_def(tablica: str, db: Session = Depends(get_db)):
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
        # Przekazanie wartości parametru w postaci słownika jako drugi argument
        result = db.execute(text(sqlstmt), {"tablica": tablica}).mappings().all()
        return [dict(row) for row in result]
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    