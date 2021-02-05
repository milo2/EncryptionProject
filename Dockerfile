FROM python:3.9

LABEL maintainer="XYZ <xyz@github.com>"
LABEL Description="Encryption service"

# Surpperess creation of .pyd files
ENV PYTHONDONTWRITEBYTECODE 1

# Pre-install
RUN python3 -m ensurepip \
    && rm -rf /tmp/* /var/cache/apk/* || true \
    && pip install pipenv


WORKDIR /opt/encryptionService

# Add Pipfiles
COPY Pipfile Pipfile
COPY Pipfile.lock Pipfile.lock

# Install the application
COPY ./ ./

# Install dependencies (deploy option)
RUN set -ex && pipenv install --ignore-pipfile --deploy

CMD ["pipenv", "run", "python", "service.py"]
