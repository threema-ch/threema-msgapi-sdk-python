Release Process
===============

Signing key: <https://lgrahl.de/pub/pgp-key.txt>

1. Check the code:

   ```bash
   flake8 .
   isort -c . || isort --df .
   mypy setup.py tests examples threema
   py.test
   ```

2. Set variables:

   ```bash
   export VERSION=<version>
   export GPG_KEY=3FDB14868A2B36D638F3C495F98FBED10482ABA6
   ```

3. Update version number in ``threema/gateway/__init__.py`` and
   ``CHANGELOG.rst``, also update the URL with the corresponding tags.

   Run `python setup.py checkdocs`.

4. Do a signed commit and signed tag of the release:

   ```bash
   git add threema/gateway/__init__.py CHANGELOG.rst
   git commit -S${GPG_KEY} -m "Release v${VERSION}"
   git tag -u ${GPG_KEY} -m "Release v${VERSION}" v${VERSION}
   ```

5. Build source and binary distributions:

   ```bash
   rm -rf build dist threema.gateway.egg-info
   find . \( -name \*.pyc -o -name \*.pyo -o -name __pycache__ \) -prune -exec rm -rf {} +
   python setup.py sdist bdist_wheel
   ```

6. Sign files:

   ```bash
   gpg --detach-sign -u ${GPG_KEY} -a dist/threema.gateway-${VERSION}.tar.gz
   gpg --detach-sign -u ${GPG_KEY} -a dist/threema.gateway-${VERSION}*.whl
   ```

7. Upload package to PyPI and push:

   ```bash
   twine upload "dist/threema.gateway-${VERSION}*"
   git push
   git push --tags
   ```

8. Create a new release on GitHub.

9. Prepare CHANGELOG.rst for upcoming changes:

   ```rst
   `Unreleased`_ (YYYY-MM-DD)
   --------------------------

   ...

   .. _Unreleased: https://github.com/lgrahl/threema-msgapi-sdk-python/compare/<VERSION>...HEAD
   ```

10. Pat yourself on the back and celebrate!
