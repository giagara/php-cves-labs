#!/bin/bash
echo 0 > /proc/sys/kernel/randomize_va_space 2>/dev/null || true

echo "=== PHP-FPM Symbol Extraction ==="
DTOR=$(readelf --dyn-syms /usr/local/sbin/php-fpm | grep ' zval_ptr_dtor$' | awk '{print $2}')
CALL=$(readelf --dyn-syms /usr/local/sbin/php-fpm | grep ' zend_call_function$' | awk '{print $2}')
echo "zval_ptr_dtor=0x${DTOR}"
echo "zend_call_function=0x${CALL}"

if [ -n "$DTOR" ] && [ -n "$CALL" ]; then
    DTOR_DEC=$((16#$DTOR))
    CALL_DEC=$((16#$CALL))
    DELTA=$(( DTOR_DEC - CALL_DEC ))
    printf "delta=0x%x\n" $DELTA
fi
echo "================================="

exec php-fpm --nodaemonize
