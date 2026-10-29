#!/usr/bin/env bash
# uptime probe (GitHub Actions edition): one-shot endpoint probe
# from a GitHub-hosted runner — a vantage point in an independent network.
# Checks: TCP connect, TLS+HTTP with
# each allowed SNI, certificate expiry, QUIC/HTTP3 handshake.
# No persistent state: exits non-zero on failure; the workflow alerts on a
# failed run (single-run sensitivity, no streak smoothing).

set -u

PORT=${TT_ENDPOINT_PORT:-443}
EXPECT_CODE=${TT_EXPECT_HTTP_CODE:-407}
EXPECT_CONNECT_CODE=${TT_EXPECT_CONNECT_CODE:-}
WARN_DAYS=${TT_CERT_WARN_DAYS:-14}
: "${TT_ENDPOINT_IP:?set TT_ENDPOINT_IP}"
: "${TT_SNI_1:?set TT_SNI_1}"

now=$(date -u +%Y-%m-%dT%H:%M:%SZ)
reasons=()

probe_tcp() {
    timeout 5 bash -c "</dev/tcp/${TT_ENDPOINT_IP}/${PORT}" 2>/dev/null
}

# HTTPS GET with a pinned SNI; echoes "code:time_appconnect_s" or fails.
probe_tls_http() {
    local sni=$1
    curl -sk --resolve "${sni}:${PORT}:${TT_ENDPOINT_IP}" "https://${sni}/" \
        -o /dev/null --max-time 10 \
        -w '%{http_code}:%{time_appconnect}' 2>/dev/null
}

# QUIC handshake via aioquic (CERT_NONE: the cert is issued for another name
# than the masquerade SNI; handshake success is the signal).
probe_quic() {
    local sni=$1
    timeout 15 python3 "$(dirname "$0")/quic_probe.py" \
        "$TT_ENDPOINT_IP" "$PORT" "$sni" 2>/dev/null
}

probe_cert_days() {
    local sni=$1 pem end days
    pem=$(timeout 10 openssl s_client -connect "${TT_ENDPOINT_IP}:${PORT}" \
        -servername "$sni" </dev/null 2>/dev/null |
        openssl x509 -noout -subject -enddate 2>/dev/null) || return 1
    if [[ -n "${TT_CERT_CN_EXPECTED:-}" ]]; then
        [[ "$pem" == *"CN=${TT_CERT_CN_EXPECTED}"* || "$pem" == *"$TT_CERT_CN_EXPECTED"* ]] || {
            echo "cert_cn_mismatch"; return 1
        }
    fi
    end=$(grep '^notAfter=' <<<"$pem" | cut -d= -f2)
    [[ -n "$end" ]] || return 1
    end_s=$(date -d "$end" +%s)
    days=$(( (end_s - $(date +%s)) / 86400 ))
    echo "$days"
}

# --- run probes -------------------------------------------------------------
tcp=FAIL
probe_tcp && tcp=OK || reasons+=("tcp_connect")

tls1=FAIL tls1_code=000
out=$(probe_tls_http "$TT_SNI_1")
if [[ "$out" == *":"* ]]; then
    tls1_code=${out%%:*}
    [[ "$tls1_code" == "$EXPECT_CODE" ]] && tls1=OK || reasons+=("tls_sni1_code_${tls1_code}")
else
    reasons+=("tls_sni1_no_answer")
fi

tls2=FAIL tls2_code=000
if [[ -n "${TT_SNI_2:-}" ]]; then
    out=$(probe_tls_http "$TT_SNI_2")
    if [[ "$out" == *":"* ]]; then
        tls2_code=${out%%:*}
        [[ "$tls2_code" == "$EXPECT_CODE" ]] && tls2=OK || reasons+=("tls_sni2_code_${tls2_code}")
    else
        reasons+=("tls_sni2_no_answer")
    fi
fi

cert_days=-1
if cert=$(probe_cert_days "$TT_SNI_1"); then
    [[ "$cert" =~ ^[0-9]+$ ]] && cert_days=$cert
else
    reasons+=("cert_probe")
fi
if (( cert_days >= 0 && cert_days < WARN_DAYS )); then
    reasons+=("cert_expires_in_${cert_days}d")
fi

quic=SKIP
if [[ ${TT_QUIC_PROBE:-1} == 1 ]]; then
    quic=FAIL
    probe_quic "${TT_SNI_2:-$TT_SNI_1}" >/dev/null && quic=OK || reasons+=("quic_handshake")
fi

# B3: unauthenticated CONNECT probe. The tunnel service must answer with its
# auth-failure code (407 = auth required, 405 = camouflage) - not tunnel, not
# hang, not reset. Catches auth/camouflage-layer regressions invisible to the
# GET probe. Empty TT_EXPECT_CONNECT_CODE skips the check.
connect=SKIP connect_code=---
if [[ -n "$EXPECT_CONNECT_CODE" ]]; then
    connect=FAIL
    connect_code=$(printf 'CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nProxy-Authorization: Basic d3Jvbmc6d3Jvbmc=\r\n\r\n' |
        timeout 12 openssl s_client -quiet -connect "${TT_ENDPOINT_IP}:${PORT}" -servername "$TT_SNI_1" 2>/dev/null |
        head -1 | grep -oE '[0-9]{3}' | head -1)
    [[ "$connect_code" == "$EXPECT_CONNECT_CODE" ]] && connect=OK || reasons+=("connect_${connect_code:-none}_want_${EXPECT_CONNECT_CODE}")
fi

# --- evaluate ---------------------------------------------------------------
fail=0
((${#reasons[@]})) && fail=1
overall=OK; ((fail)) && overall=FAIL

echo "$now overall=$overall tcp=$tcp tls(${TT_SNI_1})=$tls1/${tls1_code} tls(${TT_SNI_2:-none})=$tls2/${tls2_code} connect=$connect/${connect_code} cert_days=$cert_days quic=$quic reasons=[${reasons[*]:-}]"

if [[ -n ${GITHUB_STEP_SUMMARY:-} ]]; then
    {
        echo "| check | result |"
        echo "|---|---|"
        echo "| TCP ${PORT} | $tcp |"
        echo "| TLS ${TT_SNI_1} | $tls1 (${tls1_code}) |"
        [[ -n "${TT_SNI_2:-}" ]] && echo "| TLS ${TT_SNI_2} | $tls2 (${tls2_code}) |"
        echo "| cert days | $cert_days |"
        echo "| QUIC | $quic |"
        echo "| CONNECT | $connect (${connect_code}) |"
        echo "| overall | **$overall** |"
    } >> "$GITHUB_STEP_SUMMARY"
fi

exit "$fail"
