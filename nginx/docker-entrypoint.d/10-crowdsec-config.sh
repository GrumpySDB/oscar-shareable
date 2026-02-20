#!/bin/sh
set -eu

envsubst \
  < /etc/crowdsec/bouncers/crowdsec-nginx-bouncer.conf.template \
  > /etc/crowdsec/bouncers/crowdsec-nginx-bouncer.conf
