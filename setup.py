from setuptools import setup, find_packages

setup(
    name='dfat',
    version='1.0.0',
    description='Digital Forensics Analysis Tool (DFAT) - Professional Edition',
    author='Douglas Yu',
    author_email='doug@example.com',
    packages=find_packages(),
    install_requires=[
        'PyQt5>=5.15.0',
        'paramiko>=2.11.0',
        'cryptography>=3.4.0',
        'pyyaml>=5.4.0',
        'pillow>=8.0.0',
        'sqlalchemy>=1.4.0',
    ],
    entry_points={
        'console_scripts': [
            'dfat=dfat.main:main',
        ],
    },
    python_requires='>=3.8',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Information Technology',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Topic :: Security',
        'Topic :: System :: Systems Administration',
    ],
)
