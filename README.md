# Censys MySQL Scanner

This small utility scans provided ip addresses for MySQL servers and outputs
some brief information from the initial handshake packet.

## Usage

First make sure Go is installed on your system and present in your `$PATH`
variable (or the equivalent for Windows).

Now run it as any other Go program, any number of addresses may be provided:

```sh
go run main.go 'host1:port1' 'host2:port2'
```

For example, if you have a MySQL server running at the default port 3306 on your
local machine, running

```sh
go run main.go 'localhost:3306'
```

will return something like

```text
Address 'localhost:3306' is likely a MySQL server!
Initial Handshake Information:
        Protocol Version: 10
        Server Version: 8.3.0
        Connection ID: 26
        Charset: ff
        Capabilities: 11011111111111111111111111111111
        Status: 10
```

If the address is not a MySQL server, for example on a random port 1234 without
a running server, you'll get something like

```text
Address 'localhost:1234' is likely not a MySQL server (encountered error: 'dial tcp 127.0.0.1:1234: connect: connection refused')
```
