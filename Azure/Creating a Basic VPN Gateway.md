---
title: Creating a Basic VPN Gateway
tags:
  - Azure
publish: true
---
The Basic VPN gateway is often all that's needed, and price-wise, it's around $30/month vs VpnGW1 at $136/month. However, due to the sunset of [Basic Public IPs] (https://azure.microsoft.com/en-us/updates/upgrade-to-standard-sku-public-ip-addresses-in-azure-by-30-september-2025-basic-sku-will-be-retired/  used by the Basic VPN gateway, creating a new instance of the Basic VPN Gateway is no longer possible via the portal. Thankfully, it's still possible via a ARM template.

Prerequisites:
- VNet with a Gateway Subnet already created
- Basic Public IP with dynamic addressing

ARM Template. Replace the parameters with the appropriate URLs of your resources.

``` json
{

    "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",

    "contentVersion": "1.0.0.0",

    "parameters": {

        "virtualNetworkGateways_VPN_Gateway_name": {

            "defaultValue": "VPN_Gateway_Basic",

            "type": "string"

        },

        "publicIPAddresses_VPN_PublicIP_externalid": {

            "defaultValue": "subscriptions/XXXXXX/resourceGroups/XXXXX/providers/Microsoft.Network/publicIPAddresses/XXXXX",

            "type": "string"

        },

        "virtualNetworks_Main_externalid": {

            "defaultValue": "subscriptions/XXXXXX/resourceGroups/XXXXX/providers/Microsoft.Network/virtualNetworks/XXXXX",

            "type": "string"

        }

    },

    "variables": {},

    "resources": [

        {

            "type": "Microsoft.Network/virtualNetworkGateways",

            "apiVersion": "2017-06-01",

            "name": "[parameters('virtualNetworkGateways_VPN_Gateway_name')]",

            "location": "eastus",

            "properties": {

                "enablePrivateIpAddress": false,

                "ipConfigurations": [

                    {

                        "name": "default",

                        "id": "[concat(resourceId('Microsoft.Network/virtualNetworkGateways', parameters('virtualNetworkGateways_VPN_Gateway_name')), '/ipConfigurations/default')]",

                        "properties": {

                            "privateIPAllocationMethod": "Dynamic",

                            "publicIPAddress": {

                                "id": "[parameters('publicIPAddresses_VPN_PublicIP_externalid')]"

                            },

                            "subnet": {

                                "id": "[concat(parameters('virtualNetworks_Main_externalid'), '/subnets/GatewaySubnet')]"

                            }

                        }

                    }

                ],

                "natRules": [],

                "virtualNetworkGatewayPolicyGroups": [],

                "disableIPSecReplayProtection": false,

                "sku": {

                    "name": "Basic",

                    "tier": "Basic"

                },

                "gatewayType": "Vpn",

                "vpnType": "RouteBased",

                "activeActive": false,

                "vpnGatewayGeneration": "Generation1",

                "allowRemoteVnetTraffic": false,

                "allowVirtualWanTraffic": false

            }

        }

    ]

}
```