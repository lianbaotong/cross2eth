#!/usr/bin/env bash
set -e
set -o pipefail

export COMPOSE_PROJECT_NAME="$1"
DAPP_COMPOSE_FILE="docker-compose-cross2eth.yml"
export COMPOSE_FILE="docker-compose.yml:${DAPP_COMPOSE_FILE}"

echo "=========== # down docker-compose ============="
echo "=========== # env setting ============="
echo "COMPOSE_FILE=$COMPOSE_FILE"
echo "COMPOSE_PROJECT_NAME=$COMPOSE_PROJECT_NAME"

function down() {
    echo "============ down start ================="
    echo "=========== # docker-compose ps ============="
    docker-compose ps
    mapfile -t remains < <(docker-compose ps -q | awk '{print $1}')
    # shellcheck disable=SC2154
    num=${#remains[@]}
    echo "container num=$num"
    if [ "$num" -gt 0 ]; then
        # remove exsit container
        echo "=========== # docker-compose down ============="
        docker-compose down --rmi local
    fi
    echo "============ down end ================="
}

down
