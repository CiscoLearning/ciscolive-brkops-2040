# Config Notes For NSO

## vCenter

We need the following NED settings:

```text
ned-settings vmware-vsphere device-flavor portgroup-cfg
ned-settings vmware-vsphere connection ssl-version TLSv1.2
ned-settings vmware-vsphere connection ssl accept-any true
out-of-sync-commit-behaviour accept
```

## UCS

We need the following NED settings:

```text
ned-settings cisco-ucs console expect-timeout 3000
ned-settings cisco-ucs connection ssh client ganymed
out-of-sync-commit-behaviour accept
```

We also need to use a proxy jump host with ssh-rsa Kex enabled.

## Nexus

We need the following NED settings:

```text
ned-settings cisco-nx behaviours force-join-channel-group enable
```
