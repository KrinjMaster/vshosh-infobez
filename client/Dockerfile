FROM python:3.11-slim

# Устанавливаем системные зависимости: git + nodejs + npm
RUN apt-get update && apt-get install -y \
    git \
    nodejs \
    npm \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Python зависимости клиента
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Клонируем репозиторий генератора логов
# 🔴 ЗАМЕНИ URL НА СВОЙ РЕПОЗИТОРИЙ
RUN git clone https://github.com/summved/log-generator.git /app/log-generator

# Устанавливаем npm-зависимости генератора
WORKDIR /app/log-generator
RUN npm install

# Возвращаемся в рабочую директорию клиента
WORKDIR /app

# Копируем клиентский код
COPY . .

# Чтобы Python видел генератор (если нужно)
ENV PYTHONPATH="/app:/app/log-generator"

CMD ["python3","-u", "main.py"]
