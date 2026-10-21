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
session.use_only_cookies = 0\n\
session.use_strict_mode = 0\n\
session.serialize_handler = php\n\
display_errors = On\n\
error_reporting = E_ALL\n\
file_uploads = On\n\
upload_max_filesize = 128M\n\
post_max_size = 128M\n\
' > /usr/local/etc/php/conf.d/vuln.ini \
 && mkdir -p /tmp/sessions && chmod 1777 /tmp/sessions

COPY webroot/ /var/www/html/
EXPOSE 80
