FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && useradd --uid 1000 --create-home sentinel && mkdir /data && chown sentinel:sentinel /data
COPY . .
RUN python models/train_models.py
USER sentinel
EXPOSE 8000
CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]
