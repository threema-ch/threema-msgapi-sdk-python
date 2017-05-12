import ast
import os
import sys

from setuptools import setup


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
py_version = sys.version_info[:2]
if py_version < (3, 4):
    raise Exception("threema.gateway requires Python >= 3.4")

# Test requirements
# Note: These are just tools that aren't required, so a version range
#       is not necessary here.
tests_require = [
    'pytest>=2.8.4',
    'pytest-asyncio>=0.2.0',
    'pytest-cov>=2.4.0',
    'flake8>=3.3.0',
    'isort>=4.2.5',
    'collective.checkdocs>=0.2',
    'Pygments>=2.2.0',  # required by checkdocs
    'mypy==0.501',
]

setup(
    name='threema.gateway',
    version=get_version(),
    packages=['threema', 'threema.gateway'],
    namespace_packages=['threema'],
    install_requires=[
        'py_lru_cache>=0.1.4,<0.2',
        'logbook>=1,<2',
        'libnacl>=1.5,<2',
        'click>=6.7,<7',  # doesn't seem to follow semantic versioning
        'aiohttp>=1.3.5,<2',
        'wrapt>=1.10.10,<2',
    ],
    tests_require=tests_require,
    extras_require={
        ':python_version<="3.4"': [
            'asyncio==3.4.3',
        ],
        ':python_version<="3.5"': [
            'typing>=3.6,<3.7',
        ],
        'dev': tests_require,
        'uvloop': ['uvloop>=0.8.0,<2'],
    },
    include_package_data=True,
    entry_points={
        'console_scripts': [
            'threema-gateway = threema.gateway.bin.gateway_client:main',
            'threema-callback-server = threema.gateway.bin.callback_server:main',
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
