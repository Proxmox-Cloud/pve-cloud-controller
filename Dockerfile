FROM python:alpine3.19

# empty by default, using official pypi
ARG LOCAL_PYPI_IP

# install requirements in seperate layer
COPY requirements.txt ./

RUN if [ -n "$LOCAL_PYPI_IP" ]; then \
        echo "Running tdd build"; \
        pip install --upgrade --index-url http://$LOCAL_PYPI_IP:8088/simple --trusted-host $LOCAL_PYPI_IP -r requirements.txt; \
    else \
        echo "Running normal build"; \
        pip install -r requirements.txt; \
    fi

# install the package
COPY pyproject.toml ./
COPY src/ ./src/

RUN pip install --no-deps .

ENV PYTHONUNBUFFERED=1