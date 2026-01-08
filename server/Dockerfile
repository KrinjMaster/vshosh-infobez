FROM python:3.11-slim

RUN apt-get update && apt-get install -y sqlite3 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY . .

RUN pip install --no-cache-dir -r requirements.txt

RUN python -c "from models import init_db; init_db()"

EXPOSE 8000
CMD ["python", "main.py"]
