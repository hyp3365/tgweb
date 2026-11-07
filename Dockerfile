FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py index.html ./
RUN mkdir -p data
EXPOSE 9393
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "9393"]
