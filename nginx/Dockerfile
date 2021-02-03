FROM nginx:stable

COPY ./nginx.conf /etc/nginx/nginx.conf
COPY ./site.conf /etc/nginx/conf.d/default.conf

RUN touch /var/run/nginx.pid && \
  chown -R www-data:www-data /var/run/nginx.pid && \
  chown -R www-data:www-data /var/cache/nginx

USER www-data

VOLUME /var/www
