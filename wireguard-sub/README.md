# wireguard-sub

## Description

Wireguard subordinate charm.

A default deployment sets up a wireguard endpoint at port: 51820/udp

For more information about how to setup a remote peer See: https://www.wireguard.com/quickstart/


## Deploy

    juju deploy tiny-bash
    juju deploy wireguard-sub
    juju relate wireguard-sub tiny-bash
    juju expose wireguard-sub
    juju run-action wireguard-sub/0 get-public-key --wait

## Example setup for remote client/peer.

Create your clients config:

    [Interface]
    ## This Desktop/client's private key ##
    PrivateKey = wEgGvLxhVwWZ+5Bzl7znPl2dsr6PFKaTanfPAGHDdWc=
    
    ## local ip:port for wg0 ##
    Address = 10.8.0.2/24
    ListenPort = 58570
    
    [Peer]
    ## Remote peer public key ##
    PublicKey = lqsU0PCI1fHhQvbIq5XcdreNt+Q9lS3RNPRqS0XhOlU=
    
    ## Allowed remote traffic for this peer ##
    AllowedIPs = 10.8.0.0/24
    
    ## Remote peer's public IPv4/IPv6 address and port ##
    Endpoint = 10.51.45.175:51820
    
    ##  Key connection alive ##
    PersistentKeepalive = 15

With this config, replace the Peer's **Publickey** with that from 

    juju run-action wireguard-sub/0 get-public-key --wait

Replace the **Endpoint** with the public address of the instance/unit.

Then finally add your peer to the unit with 

    juju run-action wireguard-sub/0 add-peer publickey="YOURPUBLICKEY" endpoint="YOURENDPOINT:58570" allowedips="10.8.0.0/24" persistentkeepalive=15 --wait

## (Action) [add-peer](actions.yaml)
Documentation on this action here: [actions.yaml](actions.yaml)

    juju run-action wireguard-sub/0 add-peer publickey="LarqVX5tzZXZxFXRCnC/1TzNfncxtWSepA8ojntqVyw=" endpoint="10.51.45.42:58570" allowedips="10.8.0.0/24" persistentkeepalive=15 --wait

## (Action) [remove-peer](actions.yaml)
Documentation on this action here: [actions.yaml](actions.yaml)

    juju run-action wireguard-sub/0 remove-peer publickey="LarqVX5tzZXZxFXRCnC/1TzNfncxtWSepA8ojntqVyw=" --wait

## (Action) [get-public-key](actions.yaml)
Documentation on this action here: [actions.yaml](actions.yaml)

    juju run-action wireguard-sub/0 get-public-key --wait

## (Action) [up](actions.yaml)
This action brings up the VPN and enables the service.

    juju run-action wireguard-sub/0 up --wait

## (Action) [down](actions.yaml)
This action brings dwon the VPN and disables the service.

    juju run-action wireguard-sub/0 down --wait

## Source code
https://github.com/erik78se/charm-wireguard-sub