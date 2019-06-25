Spore Seeder for Perl on OpenBSD
====

This is an experimental implementation of spore-seeder in Perl for OpenBSD. It can be run as standalone program, or as a system service.

Command Line Options
----

```
Usage: perl spore-seeder.pl [option(s)]
 The options are:
  -u, --url             Set the spore server address. Default: rootofqaos.com
  -c, --certificate     Retrieve the Spore server certificate chain.
  -i, --info            Retrieve information about the Spore service.
  -s, --service         Run in system service mode.
  -n, --no-sig          Skip signature verification.
  -v, --verbose         Show additional messages.
  -h, --help            Display this information.
```

Standalone Program
----

To run spore-seeder as standalone program, run the following command:

```
./spore-seeder.pl
```

It will get the entropy from default server `rootofqaos.com` and add the entropy to `/dev/urandom`.

Use the `-v` option to show informational messages:

```
./spore-seeder.pl -v
```

Use the `-u` option to set the spore server:

```
./spore-seeder.pl -u rootofqaos.com -v
```

Run as System Service
----

To install and run as a system service:

```
sudo ./install.sh
```

The above command installs spore-seeder as a system service and starts service. The service runs as “spore” user. To confirm that the service is running:

```
ps -ef | grep spore
```

To stop the service:
```
rcctl stop sporeseeder
```

To start the service again:
```
rcctl start sporeseeder
```

By default, spore-seeder polls the spore server every 180 seconds. The interval can be changed in the system service configuration file. The configuration file is `/usr/local/etc/spore-seeder/spore-seeder-service.config`. Here is an example of the service configuration file:


```
# Default configurations for the Spore Seeder Service

# This is the queried Spore server's address.
address=rootofqaos.com

# This value indicates whether or not the signature should be verified.
# Set to false if the signature should not be verified.
verify=True

# How often spore-seeder should poll the server, in seconds.
# This value is used when autoSeed is False.
pollInterval=180
```



