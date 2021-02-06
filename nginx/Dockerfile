FROM nginx:stable

COPY ./nginx.conf /etc/nginx/nginx.conf
COPY ./site.conf /etc/nginx/conf.d/default.conf

RUN touch /var/run/nginx.pid && \
  chown -R www-data:www-data /var/run/nginx.pid && \
  chown -R www-data:www-data /var/cache/nginx && \
  mkdir -p /var/www/files /var/www/api/.wb_generator /var/www-config && \
  ln -s /var/www/api/.wb_generator/libwblib.so /var/www/api/guest.so && \
  touch /var/www-config/.htaccess /var/www/api/auth.so

USER www-data

VOLUME /var/www/files
VOLUME /var/www/api/.wb_generator
