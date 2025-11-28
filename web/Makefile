COMPOSE = docker compose

## go-web helper Makefile

## Show this help
help:
	@awk 'BEGIN{FS=":";hdr=1} \
	{if(hdr&&$$0~/^##/){sub(/^##[ ]?/,"");gsub(/\\033/,"\033");print;next} \
	  else if(hdr&&$$0!~/^##/){hdr=0;print ""; \
	  printf "\033[36m%-18s\033[0m %s\n","Target","Description"; \
	  printf "\033[36m%-18s\033[0m %s\n","------","-----------"} \
	 if($$0~/^##/){desc=$$0;sub(/^##[ ]*/,"",desc);getline; \
	  if($$0~/^[A-Za-z0-9_.%+-]+[ ]*:/){split($$0,a,":"); \
	  printf "\033[36m%-18s\033[0m %s\n",a[1],desc}}}' $(MAKEFILE_LIST)

## Build all service images
build:
	$(COMPOSE) build

## Up all services (db + app) in background
up:
	$(COMPOSE) up -d

## Up only db service
up-db:
	$(COMPOSE) up -d db

## Up only app service
up-app:
	$(COMPOSE) up -d app

## Stop and remove all services
down:
	$(COMPOSE) down

## Restart all services
restart:
	$(COMPOSE) down
	$(COMPOSE) up -d

## Follow logs of all services
logs:
	$(COMPOSE) logs -f

## Show service status
ps:
	$(COMPOSE) ps

## Open mysql client inside db container
db-shell:
	$(COMPOSE) exec db mysql -uapp -papppass cleanweb

## Open shell inside app container
app-shell:
	$(COMPOSE) exec app sh

## Open shell inside specified service (e.g. `make in-db`, `make in-app`)
in-%:
	$(COMPOSE) exec $* sh

.PHONY: help build up up-db up-app down restart logs ps db-shell app-shell in-%
