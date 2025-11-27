FROM python:alpine3.19
ARG PY_PVE_CLOUD=0.8.4
ENV PY_PVE_CLOUD=${PY_PVE_CLOUD}

# empty by default, using official pypi
ARG LOCAL_PYPI_IP=

# install requirements in seperate layer
COPY requirements.txt ./

RUN pip install ${LOCAL_PYPI_IP:+--index-url http://$LOCAL_PYPI_IP:8088/simple }${LOCAL_PYPI_IP:+--trusted-host $LOCAL_PYPI_IP }-r requirements.txt

RUN pip install ${LOCAL_PYPI_IP:+--index-url http://$LOCAL_PYPI_IP:8088/simple }${LOCAL_PYPI_IP:+--trusted-host $LOCAL_PYPI_IP }py-pve-cloud==$PY_PVE_CLOUD

# install the package
COPY pyproject.toml ./
COPY src/ ./src/

RUN pip install --no-deps .

ENV PYTHONUNBUFFERED=1