# ContactDiscoveryClient Tool

A command line interface for end to end testing.

## Populating registered users

The first step is to make sure the service has a set of what it considers to be registered
users. In your service configuration, you will have configured two values that are shared
secrets with the main Signal service (`userToken` and `serverToken`).

The `userToken` is used byt the Signal service to generate per-user authentication tokens.
The `serverToken`  is used directly as a shared secret to authenticate itself to the contact
discovery micro-service.

To add the number `+14151231234` to the directory:

`````
$ cd client
$ java -jar target/contactdiscovery-client-<version>.jar -c register -h http://hostname:port -u service -p <serverToken> -s +14151231234
`````

## Performing a private contact discovery request

To perform a private contact discovery request, first generate a user's "password" using the
`userToken`.

`````
$ cd client
$ python ./gentoken.py foo <userToken>
`````

This will output something like `foo:timestamp:mac`, the full string of which is the user `foo`'s temporary password.

You can now transmit the request:

`````
$ cd client
$ printf "+14151111111\n+14152222222\n+14151231234\n+14153333333" > mycontacts
$ java -jar target/contactdiscovery-client-<version>.jar -c discover -h http://hostname:port -u foo -p <password> -m <mrenclave> -t test-ias.store -a mycontacts
`````
