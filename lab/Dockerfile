FROM php:8.2-apache

RUN echo '\
session.upload_progress.enabled = 1\n\
session.upload_progress.cleanup = 0\n\
session.upload_progress.prefix = upload_progress_\n\
session.upload_progress.name = PHP_SESSION_UPLOAD_PROGRESS\n\
session.upload_progress.freq = 1%\n\
session.upload_progress.min_freq = 0\n\
session.save_path = /tmp/sessions\n\
session.save_handler = files\n\
file_uploads = On\n\
upload_max_filesize = 50M\n\
post_max_size = 50M\n\
' > /usr/local/etc/php/conf.d/vuln.ini \
 && mkdir -p /tmp/sessions && chmod 777 /tmp/sessions

COPY webroot/ /var/www/html/
