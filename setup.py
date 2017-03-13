from setuptools import setup

requires = [
    'numpy',
    'jupyter',
    'scikit-learn',
    'scipy',
    'matplotlib',
    'python-hglib',
    'requests',
    'bs4'
]

setup(name='vulture-replication',
      install_requires=requires
)
