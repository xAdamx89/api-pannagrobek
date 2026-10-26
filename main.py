from fastapi import FastAPI, Depends
from sqlalchemy.orm import Session
from sqlalchemy import text
from database import get_db

app = FastAPI()

@app.get("/")
def read_root(db: Session = Depends(get_db)):
    # Test działania połączenia z bazą
    result = db.execute(text("SELECT 1")).scalar()
    return {"Hello": "World", "db_connected": result == 1}

@app.get("/items/{item_id}")
def read_item(item_id: int, q: str | None = None, db: Session = Depends(get_db)):
    return {"item_id": item_id, "q": q}