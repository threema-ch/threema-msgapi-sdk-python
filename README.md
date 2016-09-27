# Threema Gateway API

[![Travis](https://travis-ci.org/lgrahl/threema-msgapi-sdk-python.svg?branch=master)](https://travis-ci.org/lgrahl/threema-msgapi-sdk-python)
[![codecov](https://codecov.io/gh/lgrahl/threema-msgapi-sdk-python/branch/master/graph/badge.svg)](https://codecov.io/gh/lgrahl/threema-msgapi-sdk-python)

**threema-gateway** is a Python 3 module for the Threema gateway service. This API can
be used to send and receive text messages to and from any Threema user.

## Note

On machines where Python 3 is not the default Python runtime, you should use
``pip3`` instead of ``pip``.

## Prerequisites

```
$ sudo apt-get install python3 python3-pip
```

We recommend using the [virtualenv](https://virtualenv.readthedocs.org/en/latest/)
package to create an isolated Python environment:

```
$ sudo pip install virtualenv
$ virtualenv -p python3 threema-gateway-venv
```

You can switch into the created virtual environment *threema-gateway-venv*
by running this command:

```
$ source threema-gateway-venv/bin/activate
```

To deactivate the virtual environment, just run:

```
$ deactivate
```

## Installation

If you are using a virtual environment, activate it first.

Install the module by running:

```
$ pip install git+https://github.com/lgrahl/threema-msgapi-sdk-python.git
```

The dependency ``libnacl`` will be installed automatically. However, you may need to
[install ``libsodium``](https://download.libsodium.org/doc/installation/index.html) for ``libnacl``
to work. 

## Command Line Usage

The script ``threema-gateway`` provides a command line interface for the Threema gateway.
Run the following command to see usage information:

```
$ threema-gateway --help
```

## Feature Levels

| Level | Text | Capabilities | Image | File | Credits |
|-------|------|--------------|-------|------|---------|
| 1     | X    |              |       |      |         |
| 2     | X    | X            | X     | X    |         |
| 3     | X    | X            | X     | X    | X       |

You can see the implemented feature level by invoking the following command:

```
$ threema-gateway version
```

## Callback Server

The callback server can be used to receive messages. The demo script
``threema-callback-server`` prints out received message on the command line. Run the
following command to see usage information.
 
```
$ threema-callback-server --help
```

The script resides [here](threema/gateway/bin/callback_server.py).
