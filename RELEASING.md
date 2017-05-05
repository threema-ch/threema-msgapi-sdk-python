# Release process

Signing key: https://path-to-signing-pubkey.asc

Used variables:

    export VERSION={VERSION}
    export GPG={KEYID}

Update version number in `threema/gateway/__init__.py` and `CHANGELOG.md`:

    $EDITOR threema/gateway/__init__.py CHANGELOG.md

Do a signed commit and signed tag of the release:

    git add setup.py CHANGELOG.md
    git commit -S${GPG} -m "Release v${VERSION}"
    git tag -u ${GPG} -m "Release v${VERSION}" v${VERSION}

Build source and binary distributions:

    python3 setup.py sdist
    python3 setup.py bdist_wheel

Sign files:

    gpg --detach-sign -u ${GPG} -a dist/threema.gateway-${VERSION}.tar.gz
    gpg --detach-sign -u ${GPG} -a dist/threema.gateway-${VERSION}-py3-none-any.whl

Upload package to PyPI:

    twine3 upload dist/threema.gateway-${VERSION}*
    git push
    git push --tags

