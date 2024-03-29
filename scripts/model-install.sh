#!/bin/bash

set -eu -o pipefail

shopt -s failglob

local_path=$(dirname $0)

: ${SYSREPOCTL:=sysrepoctl}
: ${SYSREPOCFG:=sysrepocfg}
: ${SYSREPOCTL_ROOT_PERMS:=-o root:root -p 600}
: ${YANG_DIR:=$local_path/../modules}

is_yang_module_installed() {
    module=$1

    $SYSREPOCTL -l | grep --count "^$module [^|]*|[^|]*| Installed .*$" > /dev/null
}

install_yang_module() {
    module=$1

    if ! is_yang_module_installed $module; then
        echo "- Installing module $module..."
        $SYSREPOCTL -i -g ${YANG_DIR}/$module.yang $SYSREPOCTL_ROOT_PERMS
    else
        echo "- Module $module already installed."
    fi
}

enable_yang_module_feature() {
    module=$1
    feature=$2

    if ! $SYSREPOCTL -l | grep --count "^$module [^|]*|[^|]*|[^|]*|[^|]*|[^|]*|[^|]*|.* $feature.*$" > /dev/null; then
        echo "- Enabling feature $feature in $module..."
        $SYSREPOCTL -m $module -e $feature
    else
        echo "- Feature $feature in $module already enabled."
    fi
}

install_yang_module ietf-interfaces@2014-05-08
install_yang_module ieee802-dot1q-types
install_yang_module ieee802-dot1q-preemption
enable_yang_module_feature ieee802-dot1q-preemption frame-preemption

install_yang_module ieee802-dot1q-sched
enable_yang_module_feature ieee802-dot1q-sched scheduled-traffic

install_yang_module iana-if-type@2017-01-19
