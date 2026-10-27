import os
import secrets
from fastapi import FastAPI, Depends, HTTPException, Query, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from sqlalchemy.orm import Session
from sqlalchemy import text
from pydantic import BaseModel
from typing import Dict, Any, Optional
from database import get_db

# --- Konfiguracja Autoryzacji ---
security = HTTPBasic()

def verify_credentials(credentials: HTTPBasicCredentials = Depends(security)):
    # Pobieramy poświadczenia ze zmiennych środowiskowych (np. z docker-compose.yaml)
    # Domyślne wartości (admin/admin123) działają jako fallback, jeśli zmienne nie są ustawione
    correct_user = secrets.compare_digest(credentials.username, os.getenv("API_USER", "admin"))
    correct_pass = secrets.compare_digest(credentials.password, os.getenv("API_PASS", "passwd"))
    
    if not (correct_user and correct_pass):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Nieprawidłowy login lub hasło",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username

# Inicjalizacja aplikacji z globalnym wymogiem autoryzacji dla wszystkich endpointów
app = FastAPI(dependencies=[Depends(verify_credentials)])

# --- Modele Pydantic dla metod POST i PUT ---

class InsertPayload(BaseModel):
    # Słownik, gdzie klucz to nazwa kolumny, a wartość to wartość do wstawienia
    data: Dict[str, Any] 

class UpdatePayload(BaseModel):
    pk_column: str          # Nazwa kolumny klucza głównego (np. 'id')
    pk_value: Any           # Wartość klucza głównego (np. 1)
    data: Dict[str, Any]    # Słownik z polami i wartościami do aktualizacji

# --- Funkcje weryfikujące bezpieczeństwo ---

def validate_identifier(name: str):
    """Zapobiega SQL Injection dla nazw tabel i kolumn."""
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
    
    # Obsługa opcjonalnego warunku WHERE
    if where_col and where_val is not None:
        validate_identifier(where_col)
        query_str += f" WHERE {where_col} = :where_val"
        params["where_val"] = where_val
        
    try:
        # .mappings() pozwala na łatwą konwersję wyników SQL na słowniki (JSON)
        result = db.execute(text(query_str), params).mappings().all()
        return [dict(row) for row in result]
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/insert/{table}")
def generic_insert(table: str, payload: InsertPayload, db: Session = Depends(get_db)):
    validate_identifier(table)
    
    if not payload.data:
        raise HTTPException(status_code=400, detail="Brak danych do wstawienia.")
        
    columns = list(payload.data.keys())
    for col in columns:
        validate_identifier(col)
        
    # Budowanie zapytania: INSERT INTO tabela (col1, col2) VALUES (:col1, :col2)
    cols_str = ", ".join(columns)
    vals_str = ", ".join([f":{col}" for col in columns])
    
    query_str = f"INSERT INTO {table} ({cols_str}) VALUES ({vals_str}) RETURNING *"
    
    try:
        result = db.execute(text(query_str), payload.data).mappings().first()
        db.commit()
        return dict(result) if result else {"status": "success"}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(e))


@app.put("/api/update/{table}")
def generic_update(table: str, payload: UpdatePayload, db: Session = Depends(get_db)):
    validate_identifier(table)
    validate_identifier(payload.pk_column)
    
    if not payload.data:
        raise HTTPException(status_code=400, detail="Brak danych do aktualizacji.")
        
    set_clauses = []
    for col in payload.data.keys():
        validate_identifier(col)
        set_clauses.append(f"{col} = :update_{col}")
        
    set_str = ", ".join(set_clauses)
    
    # Budowanie zapytania: UPDATE tabela SET col1 = :update_col1 WHERE pk = :pk_val
    query_str = f"UPDATE {table} SET {set_str} WHERE {payload.pk_column} = :pk_val RETURNING *"
    
    # Łączenie parametrów aktualizacji i warunku klucza głównego
    params = {f"update_{k}": v for k, v in payload.data.items()}
    params["pk_val"] = payload.pk_value
    
    try:
        result = db.execute(text(query_str), params).mappings().first()
        db.commit()
        if not result:
            raise HTTPException(status_code=404, detail="Nie znaleziono rekordu do aktualizacji.")
        return dict(result)
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(e))