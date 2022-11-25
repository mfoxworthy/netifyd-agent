# Building The Netify Agent in Buildroot

## Overview

The Netify Agent and any of the plugins can be built under a Buildroot environment.

The following guide will outline the general setup, configuration, and build procedure.

## Prepare The Agent

Clone the source (recursively), and prepare the buildroot files:
```shell
git clone --recursive git@gitlab.com:netify.ai/public/netify-agent.git
cd netify-agent/

./autogen.sh && ./configure

```

## Prepare Plugins (optional)

For each plugin that you wish to include in your builds, follow these steps.

***NOTE***: The Netify Flow Actions plugin will be used as an example.

Clone and prepare the source:
```shell
git clone git@gitlab.com:netify.ai/private/netify-flow-actions.git
cd netify-flow-actions/

./autogen.sh && PKG_CONFIG_PATH=../netify-agent/ ./configure
```

Add the path to the Netify Agent's external Buildroot configuration:
```shell
cd netify-agent/deploy/buildroot/package
ln -s ../../../../netify-flow-actions/deploy/buildroot/ netify-flow-actions
cd ..
echo 'source "$BR2_EXTERNAL_netifyd_PATH/package/netify-flow-actions/Config.in"' >> Config.h
```

## Prepare Buildroot

From within your Buildroot environment, enable the external Netify buildroot path
configure the "External options" from menuconfig:
```shell
BR2_EXTERNAL=/path/to/netify-agent/deploy/buildroot make menuconfig
```

## Notes
- If you require nftables support for the Netify Flow Actions plugin, you have to edit the Buildroot `package/nftables/nftables.mk` file and add the line: `NFTABLES_INSTALL_STAGING = YES`
