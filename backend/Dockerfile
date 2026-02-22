FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install poetry
RUN pip install --no-cache-dir poetry

# Copy dependencies definitions
COPY pyproject.toml poetry.lock ./

# Install dependencies
RUN poetry config virtualenvs.create false \
    && poetry install --no-root --no-interaction --no-ansi

# Copy the rest of the application.
# We copy contents of context (./backend) into /app/backend
COPY . /app/backend/

# Expose API port
EXPOSE 8001

# Run the API
# uvicorn runs on port 8001 since docker-compose exposes 8001:8001
CMD ["uvicorn", "backend.api.main:app", "--host", "0.0.0.0", "--port", "8001"]
