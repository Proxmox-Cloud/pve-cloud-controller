FROM python:alpine3.19

# empty by default, using official pypi
ARG LOCAL_PYPI_IP
ARG INJECT_PY_PVE_CLOUD_VERSION

# install requirements in seperate layer
COPY requirements.txt ./

# todo: seperate in different layers for faster tdd rebuilds
RUN if [ -n "$LOCAL_PYPI_IP" ] && [ -n "$INJECT_PY_PVE_CLOUD_VERSION" ]; then \
        echo "Running tdd build"; \
        grep -v 'py-pve-cloud' requirements.txt > filtered_requirements.txt && \
        pip install --index-url http://$LOCAL_PYPI_IP:8088/simple --trusted-host $LOCAL_PYPI_IP -r filtered_requirements.txt && \
        pip install --index-url http://$LOCAL_PYPI_IP:8088/simple --trusted-host $LOCAL_PYPI_IP py-pve-cloud==$INJECT_PY_PVE_CLOUD_VERSION; \
    else \
        echo "Running normal build"; \
        pip install -r requirements.txt; \
    fi

# install the package
COPY pyproject.toml ./
COPY src/ ./src/

RUN pip install --no-deps .

ENV PYTHONUNBUFFERED=1