# Commands
.PHONY: all
all: composer_install lint test

.PHONY: composer_install
composer_install:
	composer install

.PHONY: lint
lint:
	vendor/bin/phpcs includes test mb-force-strong-passwords.php --standard=WordPress

.PHONY: lint-fix
lint-fix:
	vendor/bin/phpcbf includes test mb-force-strong-passwords.php --standard=WordPress

.PHONY: test
test:
	php vendor/bin/phpunit --bootstrap bootstrap.php  test/*
