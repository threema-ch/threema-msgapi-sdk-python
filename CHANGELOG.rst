Changelog
*********

`6.0.0`_ (TBD)
---------------------

General:

- Add support for Python 3.10
- Drop support for Python versions below 3.7
- Major dependencies bump to increase compatibility with other packages
- Updated all tests to work with the newest dependencies
- Changed click syntax to conform with new standard behaviour


`5.0.0`_ (2021-05-17)
---------------------

- Add custom session and session arguments to `Connection` (#55, #56)
- Remove the `fingerprint` and `verify_fingerprint` arguments, see #55 for a
  detailed explanation and how to achieve pinning

`4.0.0`_ (2021-01-23)
---------------------

General:

- Drop support for Python versions below 3.6.1.
- Remove `ReceiptType.user_ack` after deprecation. Use
  `ReceiptType.user_acknowledge` instead.
- Simplify `util.aio_run`. It does not allow for passing a specific event loop
  or closing the event loop on completion any longer.
- Rename `util.aio_run_proxy_decorator` to `aio_run_proxy`. It now always
  creates the class instance within a running event loop.

Client:

- In async mode, creation of the `Connection` instance must now be done within
  an `async` function.
- If you have used a `with` context manager block in async mode before, you
  must now do this within an `async with` asynchronous context manager. No
  change is required in blocking mode.
- `Connection.close` is now an async function.

Server:

- The callback server has been refactored and the `AbstractCallback` class has
  been removed for more flexibility and control of the underlying
  `aiohttp <https://docs.aiohttp.org>`_ server. Take a look at
  `examples/callback.py` on how to use it.
- The callback server CLI has been removed because it was redundant. The
  example provides the same functionality.

`3.1.0`_ (2020-04-21)
---------------------

- Add video message
- Fix slightly off calculation of image byte length

`3.0.6`_ (2017-09-22)
---------------------

- Migrate to aiohttp2

`3.0.5`_ (2017-07-25)
---------------------

- Fix to handle new `libnacl <https://github.com/saltstack/libnacl/pull/91>`_
  exceptions.

`3.0.4`_ (2017-05-23)
---------------------

- Fix CLI

`3.0.2`_ (2017-05-12)
---------------------

- Initial publication on PyPI

.. _6.0.0: https://github.com/lgrahl/threema-msgapi-sdk-python/compare/v5.0.0...v6.0.0
.. _5.0.0: https://github.com/lgrahl/threema-msgapi-sdk-python/compare/v4.0.0...v5.0.0
.. _4.0.0: https://github.com/lgrahl/threema-msgapi-sdk-python/compare/v3.1.0...v4.0.0
.. _3.1.0: https://github.com/lgrahl/threema-msgapi-sdk-python/compare/v3.0.6...v3.1.0
.. _3.0.6: https://github.com/lgrahl/threema-msgapi-sdk-python/compare/v3.0.5...v3.0.6
.. _3.0.5: https://github.com/lgrahl/threema-msgapi-sdk-python/compare/v3.0.4...v3.0.5
.. _3.0.4: https://github.com/lgrahl/threema-msgapi-sdk-python/compare/v3.0.2...v3.0.4
.. _3.0.2: https://github.com/lgrahl/threema-msgapi-sdk-python/compare/e982c74cbe564c76cc58322d3154916ee7f6863b...v3.0.2
