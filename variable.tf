variable "resource_group_location" {
default     = "NorthEurope"
description = "Location of the resource group."
}

variable "workspace" {
type        = string
description = "Name of the Azure Virtual Desktop workspace"
default     = "AVD-TF-Woskpace"
}

variable "hostpool" {
type        = string
description = "Name of the Azure Virtual Desktop host pool"
default     = "AVD-TF-Hostpool"
}

variable "rfc3339" {
type        = string
default     = "2024-09-24T18:43:13Z"
description = "Registration token expiration"
}

variable "prefix" {
type        = string
default     = "avdtf"
description = "Prefix of the name of the AVD machine(s)"
}
variable "deploy_location" {
  type        = string
  default     = "NorthEurope"
  description = "The Azure Region in which all resources in this example should be created."
}

variable "rg" {
  type        = string
  default     = "avd-project"
  description = "Name of the Resource group in which to deploy session host"
}

variable "rdsh_count" {
  description = "Number of AVD machines to deploy"
  default     = 2
}


variable "vm_size" {
  description = "Size of the machine to deploy"
  default     = "Standard_D2as_v5"
}


variable "local_admin_username" {
  type        = string
  default     = "localadm"
  description = "local admin username"
}


variable "vault_name" {
  type        = string
  description = "The name of the key vault to be created. The value will be randomly generated if blank."
  default     = ""
}

variable "key_name" {
  type        = string
  description = "The name of the key to be created. The value will be randomly generated if blank."
  default     = ""
}

variable "sku_name" {
  type        = string
  description = "The SKU of the vault to be created."
  default     = "prenium"
  }

variable "key_permissions" {
  type        = list(string)
  description = "List of key permissions."
  default     = ["List", "Create", "Delete", "Get", "WrapKey", "UnwrapKey","Purge", "Recover", "Update", "GetRotationPolicy", "SetRotationPolicy"]
}

variable "secret_permissions" {
  type        = list(string)
  description = "List of secret permissions."
  default     = ["Set", "Get","List","Purge","Delete"]
}

variable "key_type" {
  description = "The JsonWebKeyType of the key to be created."
  default     = "RSA"
  type        = string
  validation {
    condition     = contains(["EC", "EC-HSM", "RSA", "RSA-HSM"], var.key_type)
    error_message = "The key_type must be one of the following: EC, EC-HSM, RSA, RSA-HSM."
  }
}

variable "key_ops" {
  type        = list(string)
  description = "The permitted JSON web key operations of the key to be created."
  default     = ["decrypt", "encrypt", "sign", "unwrapKey", "verify", "wrapKey"]
}

variable "key_size" {
  type        = number
  description = "The size in bits of the key to be created."
  default     = 2048
}

variable "msi_id" {
  type        = string
  description = "The Managed Service Identity ID. If this value isn't null (the default), 'data.azurerm_client_config.current.object_id' will be set to this value."
  default     = null
}

variable "avd_users" {
  description = "Account access AVD users"
  default = [
    "user@cloud.com"
  ]
}

variable "aad_group_name_AVD" {
  type        = string
  default     = "avdtf-test-dag"
  description = "Azure Active Directory Group for AVD users"
}
variable "aad_group_virtual_Machine_Administrator_Login" {
  type        = string
  default     = "grp-virtual-Machine-Administrator-Login"
  description = "Azure Active Directory Group for rbac Virtual Machine Adminsitrator Login"
}
variable "aad_group_virtual_Machine_User_Login" {
  type        = string
  default     = "grp-virtual-Machine-User-Login"
  description = "Azure Active Directory Group for rbac Virtual Machine User Login"
}
