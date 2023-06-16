CVM_RESOURCE_GROUP ?= azure-cvm-tooling-ci
LOCATION ?= eastus
IMAGE_ID ?= -
SSH_PUB_KEY_PATH ?= ~/.ssh/id_rsa.pub
SSH_PRIV_KEY ?= $(basename $(SSH_PUB_KEY_PATH) .pub)
ADMIN_PUBLIC_KEY = $(shell cat $(SSH_PUB_KEY_PATH))
VM_NAME ?= cvm
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
		--parameters assignPublicIP=$(ASSIGN_PUBLIC_IP)

.PHONY: ssh
ssh:
	@echo "Run the following command to ssh into the VM:"
ifeq ($(ASSIGN_PUBLIC_IP),true)
	@echo "ssh -i $(SSH_PRIV_KEY) azureuser@$(VM_NAME).$(LOCATION).cloudapp.azure.com"
else
	@PRIV_IP_ADDRESS=$$(az network nic show \
		--resource-group $(CVM_RESOURCE_GROUP) \
		--name $(VM_NAME)-nic \
		--query 'ipConfigurations[0].privateIPAddress' \
		--output tsv) && \
	echo "ssh -i $(SSH_PRIV_KEY) azureuser@$${PRIV_IP_ADDRESS}"
endif

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
