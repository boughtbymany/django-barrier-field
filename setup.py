import glob
from pathlib import Path
from setuptools import setup, find_packages

from barrier_field import __version__


def build_template_files(template_dir):
    # Build template data_files
    directories = [
        template_dir
    ]
    for filename in glob.iglob(f'{template_dir}/**/*', recursive=True):
        file_path = Path(filename)
        if file_path.is_dir():
            directories.append(str(file_path))

    template_files = []
    for directory in directories:
        directory_listing = (directory, [])
        for filename in glob.iglob(f'{directory}/*', recursive=True):
            if Path(filename).is_dir():
                continue
            directory_listing[1].append(Path(filename).name)
        template_files.append(directory_listing)
    return template_files


setup(
    name='django-barrier-field',
    version=__version__,
    description='It will be your shield.',
    author='Bought By Many',
    author_email='bbm@boughtbymany.com',
    packages=find_packages(),
    data_files=build_template_files('templates'),
    url='https://boughtbymany.com',
    zip_safe=False,
    install_requires=[
        'Django==2.0.4',
        'warrant==0.6.1',
        'qrcode[pil]==6.0.0',
        'swapper==1.1.0'
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