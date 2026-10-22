sudo sed -i 's/^session.upload_progress.enabled.*/session.upload_progress.enabled = 0/' \
  /etc/php/8.4/fpm/php.ini /etc/php/8.4/cli/php.ini 2>/dev/null


sudo apt update && sudo apt upgrade $(dpkg -l 'php8.4-*' 2>/dev/null | awk '/^ii/{print $2}') -y