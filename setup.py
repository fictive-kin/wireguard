
import os
import setuptools

def readme():
    path = os.path.dirname(__file__)
    with open(os.path.join(path, 'README.rst')) as f:
        return f.read()

name = 'wireguard'
description = 'Wireguard Utilities'
version = '1.0.0'
author = 'Fictive Kin LLC'
email = 'hello@fictivekin.com'
classifiers = [
    'Development Status :: 4 - Beta',
    'License :: OSI Approved :: MIT License',
    'Programming Language :: Python :: 3.6',
    'Programming Language :: Python :: 3.7',
    'Programming Language :: Python :: 3.8',
    'Programming Language :: Python :: 3.9',
    'Programming Language :: Python :: 3.10',
    'Programming Language :: Python :: 3.11',
    'Topic :: Software Development',
    'Topic :: System :: Networking',
    'Topic :: Utilities',
]

if __name__ == "__main__":
    setuptools.setup(
        name=name,
        version=version,
        description=description,
        long_description=readme(),
        classifiers=classifiers,
        url='https://github.com/fictivekin/wireguard',
        author=author,
        author_email=email,
        maintainer=author,
        maintainer_email=email,
        license='MIT',
        python_requires=">=3.6",
        packages=[
            'wireguard',
            'wireguard.cli',
            'wireguard.utils',
        ],
        install_requires=[
            'click',
            'pynacl',
            'subnet-utils',
        ],
        scripts=[
            'bin/wireguard',
        ],
        extras_require={
            'qr': ['qrcode[pil]'],
        },
    )
