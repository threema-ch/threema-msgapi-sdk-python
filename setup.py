import ast
import os
import sys

from setuptools import (
    find_packages,
    setup,
)


def get_version():
    path = os.path.join(os.path.dirname(__file__), 'threema', 'gateway', '__init__.py')
    with open(path) as file:
        for line in file:
            if line.startswith('__version__'):
                _, value = line.split('=', maxsplit=1)
                return ast.literal_eval(value.strip())
        else:
            raise Exception('Version not found in {}'.format(path))


def read(file):
    return open(os.path.join(os.path.dirname(__file__), file)).read().strip()


# Allow setup.py to be run from any path
os.chdir(os.path.normpath(os.path.join(os.path.abspath(__file__), os.pardir)))

# Import long description
long_description = '\n\n'.join((read('README.rst'), read('CHANGELOG.rst')))

# Check python version
py_version = sys.version_info[:3]
if py_version < (3, 6, 1):
    raise Exception("threema.gateway requires Python >= 3.6.1")

# Test requirements
# Note: These are just tools that aren't required, so a version range
#       is not necessary here.
tests_require = [
    'pytest>=3.1.3,<4',
    'pytest-asyncio>=0.6.0,<0.10',
    'pytest-cov>=2.5.1,<3',
    'flake8==3.7.9',
    'isort==4.3.21',
    'collective.checkdocs>=0.2',
    'Pygments>=2.2.0',  # required by checkdocs
    'mypy==0.800',
]

setup(
    name='threema.gateway',
    version=get_version(),
    packages=find_packages(),
    namespace_packages=['threema'],
    install_requires=[
        'memoization==0.2.3',  # we're using private APIs
        'logbook>=1.1.0,<2',
        'libnacl>=1.5.2,<2',
        'click>=6.7,<7',  # doesn't seem to follow semantic versioning
        'aiohttp>=3.7.3,<4',
        'wrapt>=1.10.10,<2',
    ],
    tests_require=tests_require,
    extras_require={
        ':python_version<="3.4"': [
            'asyncio==3.4.3',
            'pytest-asyncio==0.5.0'
        ],
        ':python_version<="3.5"': [
            'typing>=3.6.1,<3.7',
        ],
        'dev': tests_require,
        'uvloop': ['uvloop>=0.8.0,<2'],
    },
    include_package_data=True,
    entry_points={
        'console_scripts': [
            'threema-gateway = threema.gateway.bin.gateway_client:main',
        ],
    },

    # PyPI metadata
    author='Lennart Grahl',
    author_email='lennart.grahl@gmail.com',
    description=('An API for the Threema gateway service to send and receive '
                 'messages including text, images, files and delivery reports.'),
    long_description=long_description,
    license='MIT License',
    keywords='threema gateway service sdk api',
    url='https://gateway.threema.ch/',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: MIT License',
        'Natural Language :: English',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3 :: Only',
        'Topic :: Communications :: Chat',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Security',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Topic :: System :: Logging',
    ],
)
