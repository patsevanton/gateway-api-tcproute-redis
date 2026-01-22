#!/bin/sh
set -e

# Подстановка переменных окружения в команду
REDIS_HOST=${REDIS_HOST:-redis1.apatsev.org.ru}
REDIS_PORT=${REDIS_PORT:-443}
REDIS_CA_CERT=${REDIS_CA_CERT:-/etc/redis-ca/ca.crt}
REDIS_INSECURE_SKIP_VERIFY=${REDIS_INSECURE_SKIP_VERIFY:-false}

echo "Подключение к Redis: ${REDIS_HOST}:${REDIS_PORT}"

TLS_ARGS="--tls -h ${REDIS_HOST} -p ${REDIS_PORT}"

if [ -f "${REDIS_CA_CERT}" ]; then
  TLS_ARGS="${TLS_ARGS} --cacert ${REDIS_CA_CERT}"
else
  if [ "${REDIS_INSECURE_SKIP_VERIFY}" = "true" ]; then
    echo "Внимание: REDIS_INSECURE_SKIP_VERIFY=true (проверка TLS отключена)" >&2
    TLS_ARGS="${TLS_ARGS} --insecure"
  else
    echo "Не найден CA сертификат: ${REDIS_CA_CERT}" >&2
    echo "Смонтируйте Secret с ca.crt или установите REDIS_INSECURE_SKIP_VERIFY=true" >&2
    exit 1
  fi
fi

# Если переданы аргументы — это команда redis-cli (PING/SET/GET/...)
if [ "$#" -gt 0 ]; then
  exec sh -c "redis-cli ${TLS_ARGS} $*"
fi

# По умолчанию — интерактивный redis-cli
exec sh -c "redis-cli ${TLS_ARGS}"
