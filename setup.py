from setuptools import setup, find_packages

setup(
    name='pyticator',
    version='1.0.0',
    url='https://github.com/aussedatlo/pyticator',
    author='Louis Aussedat',
    author_email='aussedat.louis@gmail.com',
    description='Two factor autentication module',
    packages=find_packages(),
	scripts = [
		'bin/pyticator-client',
		'bin/pyticator-server',
    ],
    install_requires=[
        'configparser >= 3.7.0',
        'crypto >= 1.25.7',
    ],
    data_files=[(
        '/etc/pyticator/',
        ['config/pyticator.conf']
    )],
)