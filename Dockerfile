FROM postgres:18.3

RUN apt-get update && \
    apt-get install -y postgresql-18-partman && \
    rm -rf /var/lib/apt/lists/*