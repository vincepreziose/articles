FROM php:8.0-fpm-alpine

RUN apk update && apk add --no-cache --virtual .phpize-deps $PHPIZE_DEPS \
    && pecl install xdebug-3.0.3 && docker-php-ext-enable xdebug \
    && docker-php-ext-install pdo pdo_mysql

RUN curl -sS https://getcomposer.org/installer | php -- \
    --install-dir=/usr/local/bin --filename=composer

WORKDIR /app
COPY . .
RUN composer install

CMD php artisan serve --host=0.0.0.0
