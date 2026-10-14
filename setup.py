from setuptools import setup, find_packages
setup(
    name='linuxways-securecheck',
    version='0.1.0',
    description='Security Audit Tool for Arch/Fedora',
    author='LinuxWays Team',
    packages=find_packages(where='src'),
    package_dir={'': 'src'},
    python_requires='>=3.6',
    entry_points={'console_scripts': ['securecheck=securecheck:main']},
)
