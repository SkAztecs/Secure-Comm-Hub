# One image for both the relay server and the clients.
FROM python:3.12-slim

WORKDIR /app

# Install dependencies first (cached layer if requirements.txt doesn't change).
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the code. Secrets and local data are excluded by .dockerignore.
COPY . .

# Run as a normal user, not root.
RUN useradd --create-home chat && chown -R chat:chat /app
USER chat

EXPOSE 9000

# Default: the relay server. docker-compose overrides this for clients.
CMD ["python", "-m", "server.relay_server", "--host", "0.0.0.0", "--port", "9000"]
