FROM python:3.6

ENV PYTHONUNBUFFERED 1
ENV PYTHONDONTWRITEBYTECODE 1

RUN apt-get update \
  # dependencies for building Python packages
  && apt-get install -y build-essential \
  # psycopg2 dependencies
  && apt-get install -y libpq-dev \
  # Translations dependencies
  && apt-get install -y gettext \
  # xmlsec dependencies
  && apt-get install -y libxmlsec1-dev \
  # cleaning up unused files
  && apt-get purge -y --auto-remove -o APT::AutoRemove::RecommendsImportant=false \
  && rm -rf /var/lib/apt/lists/* \
  && mkdir -p /rao /data \
  && adduser --uid 1001 --no-create-home --gecos root --shell /bin/sh  --home /rao rao \
  && usermod -a -G root rao
  
COPY ./compose/local/django/start ./compose/production/django/entrypoint /
COPY ./rao /rao

# Requirements are installed here to ensure they will be cached.
RUN pip install -r /rao/requirements.txt \
    && chown -R 1001:0 /rao /data \
    && chmod -R g+rwXs /data /rao

USER 1001
EXPOSE 8000
VOLUME /data

WORKDIR /
CMD ["/start"]
ENTRYPOINT ["/entrypoint"]
