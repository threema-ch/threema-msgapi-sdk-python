# Threema Gateway API

**threema-gateway** is a Python 3 module for the Threema gateway service. This API can
be used to send and receive text messages to and from any Threema user.

## Note

On machines where Python 3 is not the default Python runtime, you should use
``pip3`` instead of ``pip``.

## Prerequisites

```
$ sudo apt-get install python3 python3-pip python-virtualenv
```

We recommend using the [virtualenv](http://virtualenv.readthedocs.org/en/latest/)
package to create an isolated Python environment:

```
$ sudo pip install virtualenv
$ virtualenv -p python3 threema-gateway
```

You can switch into the created virtual environment *threema-gateway*
by running this command:

```
$ source photogram-venv/bin/activate
```

To deactivate the virtual environment, just run:

```
$ deactivate
```

## Installation

If you are using a virtual environment, activate it first.

Install the module by running:

```
$ unzip threema-gateway-*.zip
$ pip install threema-gateway
```

The dependency ``libnacl`` will be installed automatically. However, you may need to
[install ``libsodium``](http://doc.libsodium.org/installation/README.html) for ``libnacl``
to work. 

## Command Line Usage

The file ``threema-gateway`` provides a command line interface for the Threema gateway.
Run the following command to see usage information:

```
$ ./threema-gateway --help
```
