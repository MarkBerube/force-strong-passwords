# Commands
.PHONY: all
all: composer_install lint test

.PHONY: composer_install
composer_install:
	composer install

.PHONY: lint
lint:
	composer install


.PHONY: test
test:
	vendor/bin/phpunit
