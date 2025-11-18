FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . /app

EXPOSE 5000

ENV FLASK_APP=lab7_e2ee_chat.server \
    CHAT_SESSION_SECRET=change_me_session \
    CHAT_PASSWORD_SECRET=change_me_password

CMD ["python", "-m", "lab7_e2ee_chat.server"]
