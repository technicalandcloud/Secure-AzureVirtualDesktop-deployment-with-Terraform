resource "azurerm_resource_group" "rg" {
  name     = var.rg
  location = var.resource_group_location
}

resource "azurerm_virtual_network" "VNet" {
  name                = "Vnet"
  address_space       = ["10.0.0.0/16"]
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
}

# Create Subnet
resource "azurerm_subnet" "Subnet" {
  name                 = "Subnet"
  resource_group_name  = azurerm_resource_group.rg.name
  virtual_network_name = azurerm_virtual_network.VNet.name
  address_prefixes     = ["10.0.1.0/24"]
}
resource "azurerm_network_security_group" "nsg" {
  name                = "${var.prefix}-NSG"
  location            = var.deploy_location
  resource_group_name = var.rg
  security_rule {
    name                       = "HTTPS"
    priority                   = 1001
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "443"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
  depends_on = [azurerm_resource_group.rg]
}

resource "azurerm_subnet_network_security_group_association" "nsg_assoc" {
  subnet_id                 = azurerm_subnet.Subnet.id
  network_security_group_id = azurerm_network_security_group.nsg.id
}

# Create AVD workspace
resource "azurerm_virtual_desktop_workspace" "workspace" {
  name                = var.workspace
  resource_group_name = azurerm_resource_group.rg.name
  location            = azurerm_resource_group.rg.location
  friendly_name       = "${var.prefix} Workspace"
  description         = "${var.prefix} Workspace"
}

# Create AVD host pool
resource "azurerm_virtual_desktop_host_pool" "hostpool" {
  resource_group_name      = azurerm_resource_group.rg.name
  location                 = azurerm_resource_group.rg.location
  name                     = var.hostpool
  friendly_name            = var.hostpool
  validate_environment     = true
  custom_rdp_properties    = "audiocapturemode:i:1;audiomode:i:0;targetisaadjoined:i:1;"
  description              = "${var.prefix} Terraform HostPool"
  type                     = "Pooled"
  maximum_sessions_allowed = 16
  load_balancer_type       = "DepthFirst" #[BreadthFirst DepthFirst]
}

resource "azurerm_virtual_desktop_host_pool_registration_info" "registrationinfo" {
  hostpool_id     = azurerm_virtual_desktop_host_pool.hostpool.id
  expiration_date = var.rfc3339
}

# Create AVD DAG
resource "azurerm_virtual_desktop_application_group" "dag" {
  resource_group_name = azurerm_resource_group.rg.name
  host_pool_id        = azurerm_virtual_desktop_host_pool.hostpool.id
  location            = azurerm_resource_group.rg.location
  type                = "Desktop"
  name                = "${var.prefix}-dag"
  friendly_name       = "Desktop AppGroup"
  description         = "AVD application group"
  depends_on          = [azurerm_virtual_desktop_host_pool.hostpool, azurerm_virtual_desktop_workspace.workspace]
}

# Associate Workspace and DAG
resource "azurerm_virtual_desktop_workspace_application_group_association" "ws-dag" {
  application_group_id = azurerm_virtual_desktop_application_group.dag.id
  workspace_id         = azurerm_virtual_desktop_workspace.workspace.id
}
locals {
  registration_token = azurerm_virtual_desktop_host_pool_registration_info.registrationinfo.token
}

resource "azurerm_network_interface" "avd_vm_nic" {
  count               = var.rdsh_count
  name                = "${var.prefix}-${count.index + 1}-nic"
  resource_group_name = azurerm_resource_group.rg.name
  location            = azurerm_resource_group.rg.location

  ip_configuration {
    name                          = "nic${count.index + 1}_config"
    subnet_id                     = azurerm_subnet.Subnet.id
    private_ip_address_allocation = "Dynamic"
  }

  depends_on = [
    azurerm_resource_group.rg
  ]
}
data "azurerm_client_config" "current" {}
resource "random_string" "azurerm_key_vault_name" {
  length  = 13
  lower   = true
  numeric = false
  special = false
  upper   = false
}
locals {
  current_user_id = coalesce(var.msi_id, data.azurerm_client_config.current.object_id)
}

 resource "azurerm_key_vault" "vault" {
  name                       = coalesce(var.vault_name, "kv-${random_string.azurerm_key_vault_name.result}")
  location                   = azurerm_resource_group.rg.location
  resource_group_name        = azurerm_resource_group.rg.name
  tenant_id                  = data.azurerm_client_config.current.tenant_id
  sku_name                   = "premium"
  soft_delete_retention_days = 7
  enabled_for_disk_encryption = true
  purge_protection_enabled    = true

  access_policy {
    tenant_id = data.azurerm_client_config.current.tenant_id
    object_id = local.current_user_id

    key_permissions    = var.key_permissions
    secret_permissions = var.secret_permissions
  }
}
resource "random_string" "azurerm_key_vault_key_name" {
  length  = 13
  lower   = true
  numeric = false
  special = false
  upper   = false
}
resource "azurerm_key_vault_key" "key" {
  name = coalesce(var.key_name, "key-${random_string.azurerm_key_vault_key_name.result}")

  key_vault_id = azurerm_key_vault.vault.id
  key_type     = var.key_type
  key_size     = var.key_size
  key_opts     = var.key_ops

  rotation_policy {
    automatic {
      time_before_expiry = "P30D"
    }

    expire_after         = "P90D"
    notify_before_expiry = "P29D"
  }
}


 resource "azurerm_disk_encryption_set" "example" {
      name                = "encryptiondisk"
      resource_group_name = azurerm_resource_group.rg.name
      location            = azurerm_resource_group.rg.location
      key_vault_key_id    = azurerm_key_vault_key.key.versionless_id
      auto_key_rotation_enabled = true
    
      identity {
        type = "SystemAssigned"
      }
      depends_on = [azurerm_key_vault_key.key]
    }


  resource "azurerm_key_vault_access_policy" "example-disk" {
  key_vault_id = azurerm_key_vault.vault.id

  tenant_id = azurerm_disk_encryption_set.example.identity[0].tenant_id
  object_id = azurerm_disk_encryption_set.example.identity[0].principal_id

  key_permissions = [
    "List",
    "Create",
    "Delete",
    "Get",
    "WrapKey",
    "UnwrapKey",
    "Purge",
    "Recover",
    "Update",
    "GetRotationPolicy",
    "SetRotationPolicy",
  ]

}
    
    resource "azurerm_role_assignment" "example-disk" {
      scope                = azurerm_key_vault.vault.id
      role_definition_name = "Key Vault Administrator"
      principal_id         = azurerm_disk_encryption_set.example.identity.0.principal_id
    }

resource "random_password" "password" {
  count = var.rdsh_count
  length           = 16
  special          = true
  override_special = "!#$%&*()-_=+[]{}<>:?"
}

resource "azurerm_key_vault_secret" "passwordadm" {
  count        = var.rdsh_count
  name         = "passwordadmin-${count.index + 1}"
  key_vault_id = azurerm_key_vault.vault.id
  value        = random_password.password[count.index].result
}

resource "azurerm_windows_virtual_machine" "avd_vm" {
  count                 = var.rdsh_count
  name                  = "${var.prefix}-${count.index + 1}"
  resource_group_name   = azurerm_resource_group.rg.name
  location              = azurerm_resource_group.rg.location
  size                  = var.vm_size
  network_interface_ids = ["${azurerm_network_interface.avd_vm_nic.*.id[count.index]}"]
  provision_vm_agent    = true
  admin_username        = var.local_admin_username
  admin_password        = random_password.password[count.index].result
  encryption_at_host_enabled = true

  os_disk {
    name                 = "${lower(var.prefix)}-${count.index + 1}"
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
    disk_encryption_set_id = azurerm_disk_encryption_set.example.id
  }

  identity {
    type = "SystemAssigned"
  }

  source_image_reference {
    publisher = "MicrosoftWindowsDesktop"
    offer     = "Windows-10"
    sku       = "20h2-evd"
    version   = "latest"
  }


  depends_on = [
    azurerm_resource_group.rg,
    azurerm_network_interface.avd_vm_nic
  ]
  
}

resource "azurerm_virtual_machine_extension" "aad_login" {
  count                      = var.rdsh_count
  name                       = "${var.prefix}-${count.index + 1}-aadLogin"
  virtual_machine_id         = azurerm_windows_virtual_machine.avd_vm.*.id[count.index]
  publisher                  = "Microsoft.Azure.ActiveDirectory"
  type                       = "AADLoginForWindows"
  type_handler_version       = "1.0"
  auto_upgrade_minor_version = true
}
resource "azurerm_virtual_machine_extension" "vmext_dsc" {
  count                      = var.rdsh_count
  name                       = "${var.prefix}${count.index + 1}-avd_dsc"
  virtual_machine_id         = azurerm_windows_virtual_machine.avd_vm.*.id[count.index]
  publisher                  = "Microsoft.Powershell"
  type                       = "DSC"
  type_handler_version       = "2.73"
  auto_upgrade_minor_version = true

  settings = <<-SETTINGS
    {
      "modulesUrl": "https://wvdportalstorageblob.blob.core.windows.net/galleryartifacts/Configuration_09-08-2022.zip",
      "configurationFunction": "Configuration.ps1\\AddSessionHost",
      "properties": {
        "HostPoolName":"${azurerm_virtual_desktop_host_pool.hostpool.name}"
      }
    }
SETTINGS

  protected_settings = <<PROTECTED_SETTINGS
  {
    "properties": {
      "registrationInfoToken": "${local.registration_token}"
    }
  }
PROTECTED_SETTINGS

  depends_on = [
    azurerm_virtual_machine_extension.aad_login,
    azurerm_virtual_desktop_host_pool.hostpool
  ]
}
data "azuread_user" "aad_user" {
  for_each            = toset(var.avd_users)
  user_principal_name = format("%s", each.key)
}

data "azurerm_role_definition" "role" { # access an existing built-in role
  name = "Desktop Virtualization User"
}

resource "azuread_group" "aad_group" {
  display_name     = var.aad_group_name_AVD
  security_enabled = true
}

resource "azuread_group_member" "aad_group_member" {
  for_each         = data.azuread_user.aad_user
  group_object_id  = azuread_group.aad_group.id
  member_object_id = each.value["id"]
}

resource "azurerm_role_assignment" "role" {
  scope              = azurerm_virtual_desktop_application_group.dag.id
  role_definition_id = data.azurerm_role_definition.role.id
  principal_id       = azuread_group.aad_group.id
}

resource "azuread_group" "aad_group_virtual_Machine_Administrator_Login" {
  display_name     = var.aad_group_virtual_Machine_Administrator_Login
  security_enabled = true
}

resource "azuread_group" "aad_group_virtual_Machine_User_Login" {
  display_name     = var.aad_group_virtual_Machine_User_Login
  security_enabled = true
}

data "azurerm_role_definition" "virtual_Machine_Administrator_Login" { # access an existing built-in role
  name = "Virtual Machine Administrator Login"
}

resource "azurerm_role_assignment" "role_virtual_Machine_Administrator_Login" {
  scope              = azurerm_resource_group.rg.id
  role_definition_id = data.azurerm_role_definition.virtual_Machine_Administrator_Login.id
  principal_id       = azuread_group.aad_group_virtual_Machine_Administrator_Login.object_id
}

data "azurerm_role_definition" "virtual_Machine_User_Login" { # access an existing built-in role
  name = "Virtual Machine User Login"
}

resource "azurerm_role_assignment" "role_virtual_Machine_User_Login" {
  scope              = azurerm_resource_group.rg.id
  role_definition_id = data.azurerm_role_definition.virtual_Machine_User_Login.id
  principal_id       = azuread_group.aad_group_virtual_Machine_User_Login.object_id
}