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
if py_version < (3, 7, 0):
    raise Exception("threema.gateway requires Python >= 3.8")

# Test requirements
# Note: These are just tools that aren't required, so a version range
#       is not necessary here.
tests_require = [
    'pytest>=7.1.2,<8',
    'pytest-asyncio>=0.18.3,<0.19',
    'pytest-cov>=3.0.0,<4',
    'flake8==7.1.0',
    'isort==5.13.2',
    'collective.checkdocs>=0.2,<0.3',
    'Pygments>=2.12.0',  # required by checkdocs
    'mypy==1.11.0',
]

setup(
    name='threema.gateway',
    version=get_version(),
    packages=find_packages(include=["threema.*"]),
    install_requires=[
        'logbook>=1.1.0,<2',
        'libnacl>=1.5.2,<2',
        'click>=8,<9',
        'aiohttp>=3.7.3,<4',
        'wrapt>=1.10.10,<2',
    ],
    extras_require={
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
