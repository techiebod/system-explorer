#!/usr/bin/env bash
# Provision the app venues the parity comparator needs, on a lab guest.
#
# Gate 3 wants a positive-path comparison for traefik, servarr, bazarr,
# paperless and plex. Those five adapters all decline without a deployment
# receipt, so on an unprovisioned host the comparator only ever compares two
# declines — which proves nothing about the readings. This brings the real
# services up and writes the receipts they need.
#
# Runs ON the guest. Shipped as a FILE (ssh host 'bash -s' -- < this), never as
# a quoted string: a quoted payload cannot contain an apostrophe, and this one
# has several.
#
# PLEX IS NEVER CLAIMED. No PLEX_CLAIM is passed and no Plex account is
# involved, so the lab server cannot join, adopt or displace anybody's existing
# server. An unclaimed server serves its API to clients inside ALLOWED_NETWORKS
# without checking a token, which is what makes SE_PLEX_TOKEN a lab-local
# placeholder rather than a real credential.
#
# Idempotent: containers already running are left alone, and receipts are
# re-read from the live configuration every time.
set -euo pipefail

RECEIPTS=/tmp/se-lab/receipts.env
NET=selab
D="sudo docker"

mkdir -p /tmp/se-lab

say() { printf '  %s\n' "$*" >&2; }

# A container is "up" only if it is running. A created-but-exited container
# would otherwise be read as present and its receipts never appear.
running() { [ "$($D inspect -f '{{.State.Running}}' "$1" 2>/dev/null || echo false)" = true ]; }

need_image() {
    if ! $D image inspect "$1" >/dev/null 2>&1; then
        say "pulling $1"
        $D pull -q "$1" >/dev/null
    fi
}

# Wait for an HTTP endpoint to answer at all. Any status is fine — 401 proves
# the service is listening, which is all this waits for. Returns 1 on timeout
# rather than continuing, because a receipt read from a service that never came
# up is worse than a missing one.
wait_http() {
    local url=$1 tries=${2:-60} code
    for _ in $(seq "$tries"); do
        code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 "$url" || true)
        if [ -n "$code" ] && [ "$code" != 000 ]; then
            say "$url answered $code"
            return 0
        fi
        sleep 2
    done
    say "TIMEOUT waiting for $url"
    return 1
}

$D network inspect "$NET" >/dev/null 2>&1 || $D network create "$NET" >/dev/null

: >"$RECEIPTS"
emit() { printf 'export %s=%s\n' "$1" "$2" >>"$RECEIPTS"; }

# ---------------------------------------------------------------- traefik
# No credential of any kind. The docker provider is pointed at the socket so
# the routers and services traefik reports are the real containers on this
# host, not a static file someone wrote to be read back.
need_image traefik:v3.3
if ! running traefik; then
    $D rm -f traefik >/dev/null 2>&1 || true
    $D run -d --name traefik --network "$NET" \
        -p 127.0.0.1:8080:8080 -p 127.0.0.1:8081:80 \
        -v /var/run/docker.sock:/var/run/docker.sock:ro \
        traefik:v3.3 \
        --api.insecure=true \
        --providers.docker=true \
        --providers.docker.exposedbydefault=false \
        --entrypoints.web.address=:80 \
        --log.level=INFO >/dev/null
fi

# Two labelled backends, so traefik has routers and services to report rather
# than only its own dashboard. Without these the collection is structurally
# empty and a port could pass by emitting nothing.
need_image nginx:alpine
for site in alpha beta; do
    if ! running "site-$site"; then
        $D rm -f "site-$site" >/dev/null 2>&1 || true
        $D run -d --name "site-$site" --network "$NET" \
            -l traefik.enable=true \
            -l "traefik.http.routers.$site.rule=Host(\`$site.lab.invalid\`)" \
            -l "traefik.http.routers.$site.entrypoints=web" \
            -l "traefik.http.services.$site.loadbalancer.server.port=80" \
            nginx:alpine >/dev/null
    fi
done
if wait_http http://127.0.0.1:8080/api/overview; then
    emit SE_TRAEFIK_URL http://127.0.0.1:8080
fi

# ---------------------------------------------------------------- servarr
# Two instances, because SE_SERVARR_INSTANCES is a list and a single-entry list
# never exercises the per-instance naming that owns SE_<NAME>_URL.
servarr_key() {
    $D exec "$1" sed -n 's:.*<ApiKey>\(.*\)</ApiKey>.*:\1:p' /config/config.xml 2>/dev/null | tr -d '\r\n'
}

declare -A SERVARR_PORT=([radarr]=7878 [sonarr]=8989)
for app in radarr sonarr; do
    port=${SERVARR_PORT[$app]}
    need_image "lscr.io/linuxserver/$app:latest"
    if ! running "$app"; then
        $D rm -f "$app" >/dev/null 2>&1 || true
        $D run -d --name "$app" --network "$NET" \
            -p "127.0.0.1:$port:$port" \
            -e PUID=1000 -e PGID=1000 -e TZ=Etc/UTC \
            "lscr.io/linuxserver/$app:latest" >/dev/null
    fi
done

for app in radarr sonarr; do
    port=${SERVARR_PORT[$app]}
    wait_http "http://127.0.0.1:$port/api/v3/system/status" || continue
    # config.xml is written slightly after the port opens.
    key=""
    for _ in $(seq 30); do
        key=$(servarr_key "$app") || true
        [ -n "$key" ] && break
        sleep 2
    done
    if [ -z "$key" ]; then
        say "NO API KEY for $app — its receipts are omitted"
        continue
    fi
    up=$(printf '%s' "$app" | tr '[:lower:]-' '[:upper:]_')
    emit "SE_${up}_URL" "http://127.0.0.1:$port"
    emit "SE_${up}_API_KEY" "$key"
    INSTANCES="${INSTANCES:-}${INSTANCES:+,}$app"
done
if [ -n "${INSTANCES:-}" ]; then
    emit SE_SERVARR_INSTANCES "$INSTANCES"
else
    say "NO servarr instances came up — SE_SERVARR_INSTANCES is omitted"
fi

# ---------------------------------------------------------------- bazarr
# bazarr is the collector whose reference publishes a ConfigMissing row where
# the port declines. With a real key it takes the other branch entirely, so
# this venue tests the reading rather than that disagreement.
need_image lscr.io/linuxserver/bazarr:latest
if ! running bazarr; then
    $D rm -f bazarr >/dev/null 2>&1 || true
    $D run -d --name bazarr --network "$NET" \
        -p 127.0.0.1:6767:6767 \
        -e PUID=1000 -e PGID=1000 -e TZ=Etc/UTC \
        lscr.io/linuxserver/bazarr:latest >/dev/null
fi
wait_http http://127.0.0.1:6767/api/system/status || true
bkey=""
for _ in $(seq 30); do
    # bazarr has moved this file between releases; ask for whichever exists
    # rather than hard-coding the winner of that history.
    bkey=$($D exec bazarr sh -c \
        'grep -h -m1 -oE "apikey: *[a-f0-9]+" /config/config/config.yaml /config/config/config.ini 2>/dev/null \
         || grep -h -m1 -oE "apikey *= *[a-f0-9]+" /config/config/config.ini 2>/dev/null' 2>/dev/null \
        | grep -oE '[a-f0-9]{16,}' | head -1 | tr -d '\r\n') || true
    [ -n "$bkey" ] && break
    sleep 2
done
if [ -n "$bkey" ]; then
    emit SE_BAZARR_URL http://127.0.0.1:6767
    emit SE_BAZARR_API_KEY "$bkey"
else
    say "NO API KEY for bazarr — its receipts are omitted"
fi

# ------------------------------------------------------------- downloaders
# The other collector whose reference publishes a row where the port declines.
# transmission's RPC is unauthenticated on loopback, which is how the estate
# runs it and what the adapter documents; sabnzbd keeps its key in its ini.
need_image lscr.io/linuxserver/transmission:latest
if ! running transmission; then
    $D rm -f transmission >/dev/null 2>&1 || true
    $D run -d --name transmission --network "$NET" \
        -p 127.0.0.1:9091:9091 \
        -e PUID=1000 -e PGID=1000 -e TZ=Etc/UTC \
        lscr.io/linuxserver/transmission:latest >/dev/null
fi
if wait_http http://127.0.0.1:9091/transmission/rpc; then
    emit SE_TRANSMISSION_URL http://127.0.0.1:9091
fi

# 8090, not sabnzbd's own 8080: traefik's dashboard already holds that port on
# this host, and a receipt pointing at the wrong service is worse than none.
need_image lscr.io/linuxserver/sabnzbd:latest
if ! running sabnzbd; then
    $D rm -f sabnzbd >/dev/null 2>&1 || true
    $D run -d --name sabnzbd --network "$NET" \
        -p 127.0.0.1:8090:8080 \
        -e PUID=1000 -e PGID=1000 -e TZ=Etc/UTC \
        lscr.io/linuxserver/sabnzbd:latest >/dev/null
fi
if wait_http http://127.0.0.1:8090/api 90; then
    skey=""
    for _ in $(seq 30); do
        skey=$($D exec sabnzbd sh -c \
            'grep -m1 -oE "^api_key *= *[a-f0-9]+" /config/sabnzbd.ini 2>/dev/null' 2>/dev/null \
            | grep -oE '[a-f0-9]{16,}' | head -1 | tr -d '\r\n') || true
        [ -n "$skey" ] && break
        sleep 2
    done
    emit SE_SABNZBD_URL http://127.0.0.1:8090
    if [ -n "$skey" ]; then
        emit SE_SABNZBD_API_KEY "$skey"
    else
        # The URL alone is deliberate: it is the branch where the reference
        # publishes ConfigMissing rather than declining, which is the very
        # disagreement this venue exists to compare.
        say "NO API KEY for sabnzbd — the URL is emitted without it"
    fi
fi

# ---------------------------------------------------------------- paperless
# sqlite plus its own redis, so this does not disturb the redis already on the
# host that the docker collector is reading.
need_image redis:7
if ! running paperless-redis; then
    $D rm -f paperless-redis >/dev/null 2>&1 || true
    $D run -d --name paperless-redis --network "$NET" redis:7 >/dev/null
fi
need_image ghcr.io/paperless-ngx/paperless-ngx:latest
if ! running paperless; then
    $D rm -f paperless >/dev/null 2>&1 || true
    $D run -d --name paperless --network "$NET" \
        -p 127.0.0.1:8000:8000 \
        -e PAPERLESS_REDIS=redis://paperless-redis:6379 \
        -e PAPERLESS_SECRET_KEY=lab-only-not-a-secret \
        -e PAPERLESS_TIME_ZONE=Etc/UTC \
        -e PAPERLESS_ADMIN_USER=lab \
        -e PAPERLESS_ADMIN_PASSWORD=lab-only-not-a-secret \
        -e PAPERLESS_URL=http://127.0.0.1:8000 \
        ghcr.io/paperless-ngx/paperless-ngx:latest >/dev/null
fi
if wait_http http://127.0.0.1:8000/api/ 150; then
    ptok=$($D exec paperless python3 manage.py drf_create_token lab 2>/dev/null \
        | grep -oE '[a-f0-9]{40}' | head -1 | tr -d '\r\n') || true
    if [ -n "${ptok:-}" ]; then
        emit SE_PAPERLESS_URL http://127.0.0.1:8000
        emit SE_PAPERLESS_TOKEN "$ptok"
    else
        say "NO TOKEN for paperless — its receipts are omitted"
    fi
fi

# ---------------------------------------------------------------- plex
# Unclaimed, deliberately and permanently. PLEX_CLAIM is not set and must not
# be: a claim binds the server to a Plex account, and this is a throwaway VM.
# ALLOWED_NETWORKS is what makes the API answer, so the token below is a
# placeholder that satisfies the adapter's receipt check and is never validated
# by anything.
need_image lscr.io/linuxserver/plex:latest
if ! running plex; then
    $D rm -f plex >/dev/null 2>&1 || true
    $D run -d --name plex --network host \
        -e PUID=1000 -e PGID=1000 -e TZ=Etc/UTC -e VERSION=docker \
        -e ALLOWED_NETWORKS=127.0.0.0/8,192.168.122.0/24 \
        lscr.io/linuxserver/plex:latest >/dev/null
fi
if wait_http http://127.0.0.1:32400/identity 90; then
    # Prove the API answers unauthenticated before writing a receipt for it. A
    # receipt pointing at a server that returns 401 to everything would make
    # both sides fail identically, which reads as agreement.
    sec=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 \
        http://127.0.0.1:32400/library/sections || true)
    if [ "$sec" = 200 ]; then
        emit SE_PLEX_URL http://127.0.0.1:32400
        emit SE_PLEX_TOKEN lab-unclaimed-server-ignores-this
    else
        say "plex /library/sections answered $sec, not 200 — receipts omitted"
    fi
fi

say "receipts written to $RECEIPTS"
sed 's/=.*/=<set>/' "$RECEIPTS" >&2
