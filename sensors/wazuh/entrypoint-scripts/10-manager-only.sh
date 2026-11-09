#!/usr/bin/env bash
set -Eeuo pipefail

# The official manager image supervises Filebeat and stops the whole container
# when Filebeat exits. This lab has no indexer, so remove only that disposable
# container service before s6 starts supervised services.
rm -rf -- /etc/services.d/filebeat

secret=/run/secrets/wazuh_registration_password
target=/var/ossec/etc/authd.pass

if [[ ! -s "$secret" ]]; then
    printf 'Missing or empty enrollment secret: %s\n' "$secret" >&2
    exit 1
fi

install -o root -g wazuh -m 0640 "$secret" "$target"

# The persistent etc volume otherwise keeps an older copy across restarts.
rule_source=/wazuh-config-mount/etc/rules/ahr_falco_rules.xml
[[ -s "$rule_source" ]] || { printf 'Missing maintained AHR rules: %s\n' "$rule_source" >&2; exit 1; }
install -o root -g wazuh -m 0640 "$rule_source" /var/ossec/etc/rules/ahr_falco_rules.xml

