FROM php:8.3-apache

RUN a2enmod rewrite
RUN apt-get update && apt-get install -y locales-all
RUN docker-php-ext-install mysqli pdo pdo_mysql
RUN apt-get install -y libldap2-dev
RUN docker-php-ext-install ldap
RUN apt-get install -y libicu-dev
RUN docker-php-ext-install intl
