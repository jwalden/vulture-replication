from setuptools import setup

requires = [
    'numpy',
    'jupyter',
    'scikit-learn',
    'scipy',
    'matplotlib',
    'python-hglib',
    'requests',
    'bs4',
    'prettytable'
]

setup(name='vulture-replication',
      install_requires=requires
)
