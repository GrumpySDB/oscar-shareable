FROM nginx:stable

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        libnginx-mod-http-lua \
        lua5.1 \
        luarocks \
        gettext-base \
        ca-certificates \
    && luarocks install lua-resty-http 0.17.1-0 \
    && luarocks install lua-cjson 2.1.0.10-1 \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /usr/local/lua/crowdsec/plugins/crowdsec /var/lib/crowdsec/lua/templates /etc/crowdsec/bouncers

COPY lua/lib/ /usr/local/lua/crowdsec/
COPY lua/templates/ /var/lib/crowdsec/lua/templates/
COPY crowdsec_nginx.conf /etc/nginx/crowdsec_nginx.conf
COPY crowdsec-nginx-bouncer.conf.template /etc/crowdsec/bouncers/crowdsec-nginx-bouncer.conf.template
COPY docker-entrypoint.d/10-crowdsec-config.sh /docker-entrypoint.d/10-crowdsec-config.sh

RUN chmod +x /docker-entrypoint.d/10-crowdsec-config.sh
