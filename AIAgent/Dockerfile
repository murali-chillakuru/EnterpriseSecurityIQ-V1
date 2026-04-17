FROM python:3.12-slim

WORKDIR /agent

COPY AIAgent/requirements.txt .
RUN pip install --no-cache-dir --pre -r requirements.txt

# Install Playwright Chromium + OS dependencies for PDF generation
RUN playwright install --with-deps chromium

COPY AIAgent/app/ app/
COPY AIAgent/main.py .

# Web dashboard served at / — ARG busts Docker cache on rebuild
ARG CACHEBUST=1
COPY webapp/ webapp/

EXPOSE 8088

CMD ["uvicorn", "app.api:app", "--host", "0.0.0.0", "--port", "8088"]
