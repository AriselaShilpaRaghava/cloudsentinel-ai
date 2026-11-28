FROM python:3.12-slim
WORKDIR /app
COPY ml_service/requirements.txt ./ml_service/requirements.txt
RUN pip install --no-cache-dir -r ml_service/requirements.txt
COPY ml_service ./ml_service
COPY data ./data
EXPOSE 8001
WORKDIR /app/ml_service
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8001"]
