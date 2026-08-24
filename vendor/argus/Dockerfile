# Argus — minimal container image.
#   docker build -t argus .
#   docker run --rm -it argus               # interactive menu
#   docker run --rm argus ip 8.8.8.8        # one-off command
FROM python:3.12-slim

LABEL org.opencontainers.image.title="Argus" \
      org.opencontainers.image.description="The all-seeing OSINT & reconnaissance toolkit" \
      org.opencontainers.image.licenses="MIT"

WORKDIR /app

# Install dependencies first for better layer caching.
COPY requirements.txt pyproject.toml ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the project and install it.
COPY . .
RUN pip install --no-cache-dir -e .

# Reports land here; mount a volume to keep them: -v $PWD/reports:/reports
ENV ARGUS_OUTPUT_DIR=/reports
VOLUME ["/reports"]

ENTRYPOINT ["python", "-m", "argus"]
