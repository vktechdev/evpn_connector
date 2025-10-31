#!/bin/bash
# vim: tabstop=4 shiftwidth=4 softtabstop=4 expandtab ai

set -eu
set -o pipefail


DEF_SW_NAME="evpn"
CMD="${1:-create}"
CFGPATH="${2:-\"$(pwd)\"}"
SW="${3:-$DEF_SW_NAME}"
DEBUG="${4:-}"


log(){
    message="$1"
    level="${2:-INFO}"
    cur_date="$(date '+%Y-%m-%d %H:%M:%S')"
    echo "$cur_date [$level] $message"
}


# Check requirements
if [ -z "$(which ip)" ]; then
    log "Need install iproute2 package" "ERROR"
    exit 1
fi
if [ -z "$(which ovs-vsctl)" ]; then
    log "Need install openvswitch package" "ERROR"
    exit 1
fi
if [ -z "$(which jq)" ]; then
    log "Need install jq package" "ERROR"
    exit 1
fi
if [[ "$(whoami)" != "root" && ! "$DEBUG" ]]; then
    log "Please run as root" "ERROR"
    exit 1
fi


# Binary
[ -n "$DEBUG" ] && PRECMD="echo " || PRECMD=""
IP="${PRECMD}$(which ip)"
CAT="${PRECMD}$(which cat)"
JQ="${PRECMD}$(which jq)"
OVSCTL="${PRECMD}$(which ovs-vsctl)"

DEFAULT_PREFIX="16"
DEFAULT_CONFIG_TYPE="l2"

create() {
    log "Create clients dataplane"
    ls $CFGPATH | while read fl; do
        path="$CFGPATH/$fl"
        file_cfg_type="$(cat $path | jq -r '.cfg_type')"
        cfg_type="${file_cfg_type:-$DEFAULT_CONFIG_TYPE}"
        mac="$(cat $path | jq -r '.mac')"
        vni="$(cat $path | jq -r '.vni')"
        ofport="$(cat $path | jq -r '.ofport')"
        mac_concat="$(echo $mac | sed 's/://g')"
        ns_name="client_${mac_concat}_$vni"
        in_if_name="in$mac_concat"
        ex_if_name="ex$mac_concat"
        log "Create clientmac=$mac ofport=$ofport in netns $ns_name"
        $IP link add "$in_if_name" type veth peer name "$ex_if_name"
        $IP link set "$ex_if_name" up
        $IP netns add "$ns_name"
        $IP link set "$in_if_name" netns "$ns_name"
        $IP netns exec "$ns_name" ip link set lo up
        $IP netns exec "$ns_name" ip link set "$in_if_name" address "$mac"
        $IP netns exec "$ns_name" ip link set "$in_if_name" up
        if [ "$cfg_type" == "l2" ]; then
            ip="$(cat $path | jq -r '.ip')"
            $IP netns exec "$ns_name" ip address add "$ip/$DEFAULT_PREFIX" dev "$in_if_name"
        fi
        if [ "$cfg_type" == "l3" ]; then
            prefixes="$(cat $path | jq -r '.routes' | sed 's/[\[" ]//g;s/\]//g;s/,/\n/g')"
            for prefix in $prefixes; do
                ip="$(echo $prefix | sed 's/\/.*//g')"
                [ -z "$ip" ] && continue
                $IP netns exec "$ns_name" ip address add "$ip/$DEFAULT_PREFIX" dev "$in_if_name"
            done
        fi
        $OVSCTL --may-exist add-port "$SW" "$ex_if_name" -- set Interface "$ex_if_name" type=system ofport_request="$ofport"
    done
}


delete() {
    log "Delete clients dataplane"
    ls $CFGPATH | while read fl; do
        path="$CFGPATH/$fl"
        vni="$(cat $path | jq -r '.vni')"
        mac="$(cat $path | jq -r '.mac')"
        mac_concat="$(echo $mac | sed 's/://g')"
        ns_name="client_${mac_concat}_$vni"
        in_if_name="in$mac_concat"
        ex_if_name="ex$mac_concat"
        log "Delete client mac=$mac in netns $ns_name"
        $OVSCTL --if-exist del-port "$SW" "$ex_if_name"
        $IP netns del "$ns_name"
    done
}


case "$CMD" in
    create)
        create
        ;;
    delete)
        delete
        ;;
    *)
        log "Unknown command. Use {create|delete} [DEBUG]" "ERROR"
esac

exit 0
