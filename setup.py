from setuptools import setup

from barrier_field import __version__

setup(
    name='django-barrier-field',
    version=__version__,
    description='It will be your shield.',
    author='Bought By Many',
    author_email='bbm@boughtbymany.com',
    packages=['barrier_field'],
    url='https://boughtbymany.com',
    zip_safe=False,
    install_requires=[
        'Django==2.0.4',
        'warrant==0.6.1',
        'qrcode[pil]==6.0.0'
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