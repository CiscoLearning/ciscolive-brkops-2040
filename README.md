# Cisco Live Europe NSO Service

This repo contains an NSO service definition that automates the Cisco Live Europe
Data Center network.  This includes the core switching, compute networking, and
virtualization networking pieces.

## Testing the Model

In the `cml` subdirectory there is a lab topology that is used to test out
the switching components of this model.  This topology can be loaded
into Cisco Modeling Labs (2.5.1 or higher).

NSO runs in the out-of-band portion of the network and communicates with
an instance of NetBox running in a Docker container on a host in DC1.

**NB:** The NSO and NetBox bits are not included in this distribution.
