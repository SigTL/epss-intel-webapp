from setuptools import setup, find_packages

setup(
    name='epss-intel',
    version='1.2',
    packages=find_packages(),
    install_requires=[
        'requests',
        'rich',
    ],
    entry_points={
        'console_scripts': [
            'epss-intel=epss_intel.epss_intel:main',
        ],
    },
    author='Omar Santos',
    author_email='santosomar@gmail.com',
    description='A powerful CLI tool to fetch and analyze EPSS scores and CVE descriptions.',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    url='https://github.com/SigTL/epss-client',
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ],
)
