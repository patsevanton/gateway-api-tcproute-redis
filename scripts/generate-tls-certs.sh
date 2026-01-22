#!/bin/bash
set -e

echo "Генерация Root CA и TLS сертификата для Gateway..."

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

CA_KEY="/tmp/gateway-ca.key"
CA_CRT="/tmp/gateway-ca.crt"

TLS_KEY="/tmp/gateway-tls.key"
TLS_CSR="$TMP_DIR/gateway-tls.csr"
TLS_CRT_LEAF="/tmp/gateway-tls-leaf.crt"
TLS_CRT_CHAIN="/tmp/gateway-tls.crt"

DOMAIN="apatsev.org.ru"
WILDCARD="*.$DOMAIN"

# 1) Root CA (самоподписанный корневой сертификат)
openssl genrsa -out "$CA_KEY" 2048
openssl req -x509 -new -nodes -days 3650 -sha256 \
  -key "$CA_KEY" \
  -out "$CA_CRT" \
  -subj "/CN=Gateway Root CA ($DOMAIN)" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "subjectKeyIdentifier=hash"

# 2) Leaf сертификат для Gateway, подписанный Root CA
cat > "$TMP_DIR/leaf.cnf" <<EOF
[ req ]
default_bits       = 2048
prompt             = no
default_md         = sha256
distinguished_name = dn
req_extensions     = v3_req

[ dn ]
CN = $WILDCARD

[ v3_req ]
basicConstraints = critical,CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = $WILDCARD
DNS.2 = redis1.$DOMAIN
DNS.3 = redis2.$DOMAIN
EOF

openssl genrsa -out "$TLS_KEY" 2048
openssl req -new -key "$TLS_KEY" -out "$TLS_CSR" -config "$TMP_DIR/leaf.cnf"

openssl x509 -req -in "$TLS_CSR" -days 365 -sha256 \
  -CA "$CA_CRT" -CAkey "$CA_KEY" -CAcreateserial \
  -out "$TLS_CRT_LEAF" \
  -extfile "$TMP_DIR/leaf.cnf" -extensions v3_req

# 3) Цепочка (leaf + root CA) для отдачи клиентам при handhshake (на всякий случай)
cat "$TLS_CRT_LEAF" "$CA_CRT" > "$TLS_CRT_CHAIN"

# 4) Secret для Gateway (TLS keypair)
kubectl create secret tls gateway-tls-cert \
  --cert="$TLS_CRT_CHAIN" \
  --key="$TLS_KEY" \
  --dry-run=client -o yaml | kubectl apply -f -

# 5) Secret с Root CA для клиентов (app1/app2)
kubectl create secret generic gateway-root-ca \
  --from-file=ca.crt="$CA_CRT" \
  --dry-run=client -o yaml | kubectl apply -f -

echo "Готово:"
echo "- Root CA: $CA_CRT"
echo "- Gateway TLS key: $TLS_KEY"
echo "- Gateway TLS cert chain: $TLS_CRT_CHAIN"
echo "- Secrets: gateway-tls-cert, gateway-root-ca применены в кластер."
