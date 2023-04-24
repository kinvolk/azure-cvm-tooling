CVM_RESOURCE_GROUP ?= azure-cvm-tooling-ci
LOCATION ?= eastus
IMAGE_ID ?= -
SSH_PUB_KEY_PATH ?= ~/.ssh/id_rsa.pub
ADMIN_PUBLIC_KEY = $(shell cat $(SSH_PUB_KEY_PATH))
ifeq ($(SUFFIX),)
	SUFFIX := $(shell bash -c 'echo $$RANDOM | md5sum | head -c 6')
endif
VM_NAME := cvm-$(SUFFIX)
ASSIGN_PUBLIC_IP ?= false

.PHONY: deploy
deploy:
	az deployment group create \
		--template-file ./arm/cvm.bicep \
		--resource-group=$(CVM_RESOURCE_GROUP) \
		--name $(VM_NAME) \
		--parameters virtualMachineName=$(VM_NAME) \
		--parameters location=$(LOCATION) \
		$(if $(IMAGE_ID:-=),--parameters imageId=$(IMAGE_ID)) \
		--parameters adminPublicKey='$(ADMIN_PUBLIC_KEY)' \
		--parameters assignPublicIP=$(ASSIGN_PUBLIC_IP) && \
	echo -n "$(VM_NAME): " && \
	az network nic show \
		--resource-group $(CVM_RESOURCE_GROUP) \
		--name $(VM_NAME)-nic \
		--query 'ipConfigurations[0].privateIpAddress' \
		--output tsv

.PHONY: delete
delete:
	az vm delete \
		--resource-group $(CVM_RESOURCE_GROUP) \
		--name cvm-$(SUFFIX) \
		--yes && \
	az network public-ip delete \
		--resource-group $(CVM_RESOURCE_GROUP) \
		--name $(VM_NAME)-ip && \
	az network vnet delete \
		--resource-group azure-cvm-tooling-ci \
		--name $(VM_NAME)-vnet
