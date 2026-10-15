FROM python:3.12-slim-bookworm
ARG EXTRAS=api,ocr,active
ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 \
    ANTIPHISH_DATA_DIR=/data ANTIPHISH_MODEL_DIR=/models \
    ANTIPHISH_API_HOST=0.0.0.0 PLAYWRIGHT_BROWSERS_PATH=/opt/browsers \
    XDG_CACHE_HOME=/tmp/.cache TLDEXTRACT_CACHE=/tmp/tldextract
WORKDIR /app
COPY pyproject.toml ./
RUN python -c "import tomllib,os; p=tomllib.load(open('pyproject.toml','rb'))['project']; deps=p['dependencies']+sum((p['optional-dependencies'][x] for x in '${EXTRAS}'.split(',')),[]); open('/tmp/requirements.txt','w').write('\n'.join(deps))" \
    && pip install -r /tmp/requirements.txt && python -m playwright install --with-deps chromium \
    && apt-get install -y --no-install-recommends libgl1 && apt-get clean \
    && useradd --uid 10001 --create-home analyst \
    && mkdir -p /data /models && chown analyst:analyst /data /models
COPY src ./src
COPY resources ./resources
COPY setup.py MANIFEST.in README.md ./
RUN pip install --no-deps .
USER analyst
EXPOSE 8000
CMD ["antiphish-api"]
