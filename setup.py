import setuptools
from synackbot._version import __version__

setuptools.setup(
	name="SynackBot",
	version=__version__,
	author='Patrick Hener',
	url='https://github.com/patrickhener/synackbot',
	description='A powerful bot to interact with '
	'the synack api to register targets, claim missions '
	'an a lot of more things',
	long_description=(open('README.md', 'r').read()),
	long_description_content_type='text/markdown',
	license="MIT License",
	platforms=[
		"Tested on linux",
	],
	packages=setuptools.find_packages(),
	include_package_data=True,
	entry_points={
		'console_scripts': [
			'synackbot=synackbot.__main__:main'
		],
	},
	install_requires=[
		"certifi",
		"charset-normalizer",
		"idna",
		"netaddr",
		"pyotp",
		"requests",
		"urllib3",
		"tabulate",
	],
	python_requires='>=3',
	classifiers=[
		'Programming Language :: Python :: 3',
		'License :: OSI Approved :: MIT License',
	],
)