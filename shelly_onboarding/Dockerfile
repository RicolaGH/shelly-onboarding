FROM python:3.12-alpine
WORKDIR /app
RUN pip install --no-cache-dir aiohttp==3.13.3
COPY device_migrator ./device_migrator
COPY *.py *.html ./
ENTRYPOINT ["python", "-u", "app.py"]
