# Backend Dockerfile for AI Security Scanner - Production
#
# Dual-mode: Web server (default) or CLI scanner
#
# Usage:
#   docker build -f backend/Dockerfile -t ai-scanner .
#
#   # Web server (default)
#   docker run -p 8000:8000 ai-scanner
#   docker run -p 8000:8000 ai-scanner web
#
#   # CLI scanner
#   docker run ai-scanner scan https://your-app.com
#   docker run ai-scanner https://your-app.com  # auto-detect
#   docker run -v $(pwd)/reports:/reports ai-scanner scan https://app.com -o /reports/report.html
#
#   # CLI commands
#   docker run ai-scanner version
#   docker run ai-scanner --help

FROM python:3.11-slim AS production

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    # WeasyPrint dependencies for PDF generation (per official docs)
    libpango-1.0-0 \
    libpangoft2-1.0-0 \
    libharfbuzz-subset0 \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN adduser --system --group app

# Install poetry
RUN pip install --no-cache-dir poetry && \
    poetry config virtualenvs.create false

# Copy dependency files from root context
COPY pyproject.toml poetry.lock* ./

# Install production dependencies only (--no-root skips installing the project itself)
RUN poetry install --only main --no-interaction --no-ansi --no-root

# Copy application code
COPY backend/ ./backend/

# Copy and set up entrypoint
COPY backend/docker-entrypoint.sh ./docker-entrypoint.sh
RUN chmod +x ./docker-entrypoint.sh

RUN chown -R app:app /app

USER app

ENV PORT=8000
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV ENVIRONMENT=production

EXPOSE 8000

ENTRYPOINT ["./docker-entrypoint.sh"]
CMD ["web"]
