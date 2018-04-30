from setuptools import setup

from barrier_field import __version__

setup(
    name='barrier_field',
    version=__version__,
    description='It will be your shield.',
    author='Bought By Many',
    author_email='bbm@boughtbymany.com',
    packages=['barrier_field'],
    url='https://boughtbymany.com',
    zip_safe=False,
    install_requires=[
        'warrant==0.6.1'
    ],
    include_package_data=True,
    classifiers=[
        'Environment :: Web Environment',
        'Framework :: Django',
        'Intended Audience :: Developers',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
    ]
)