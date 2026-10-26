FROM python:3.11-slim

WORKDIR /app

# Instalacja Poetry
RUN pip install --no-cache-dir poetry

# Kopiowanie plików konfiguracyjnych Poetry
COPY pyproject.toml poetry.lock* ./

# Instalacja zależności (bez instalowania samego projektu jako paczki)
RUN poetry config virtualenvs.create false \
    && poetry install --no-root --no-interaction --no-ansi

# Kopiowanie reszty kodu
COPY . .

# Uruchomienie Uvicorn (FastAPI) z przeładowywaniem w locie
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]