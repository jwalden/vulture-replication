# vulture-replication
Replication study of the "Vulture" paper "Predicting Vulnerable Software Components" (CCS'07)

## Setup
This project makes use of Python 2.7, although Python 3.4+ should work as well. You can either use Anaconda or set up a virtual environment.

### Using virtualenv
1. Create a virtual environment and activate it:

    **Python 2.7:**
```
virtualenv venv
source venv/bin/activate
```


    **Python 3.4+:**
```
python3 -m venv venv
source venv/bin/activate
```

2. Install all the dependencies in the virtual environment:
```
pip install -e .
```

### Using Anaconda
Anaconda is a Python distribution with most if not all of the required modules preinstalled. You can find it on `https://www.continuum.io`.


## Usage
### Jupyter Notebooks
Run the Jupyter Server:
```
jupyter notebook
```
This should open Jupyter in a browser window at `http://localhost:8888`. From there you can open, modify and run the individual notebooks.

### Miner
There is a basic run script for the miner application, located in the miner directory. It has to be run from the project root directory:
```
python miner/runscript.py
```

There is also a basic help for the script:
```
$ python miner/runscript.py --help
usage: runscript.py [-h] [--scrape-overview] [--scrape-advisories]
                   [--extract-advisories] [--build-index repopath]

Miner for building an index of vulnerability-affected Mozilla components. It
combines the Mozilla Foundation Security Advisories (MFSA) with the commits in
the mozilla-central mercurial repository.

optional arguments:
 -h, --help            show this help message and exit
 --scrape-overview     scrape and store the MFSA overview page
 --scrape-advisories   scrape and store the individual advisory pages
 --extract-advisories  parse stored advisory pages and store found bug
                       numbers
 --build-index repopath
                       build the index for the given repository path and
                       store it
```

**IMPORTANT:** Please note that scraping the individual advisories will send 1000+ HTTP requests to Mozilla in a short amount of time. Because of this, the individual advisory pages are stored in data/miner/advisories/.

#### Log File
The output of the script is quite basic. If you want to see more detailed output, you can
observe the log output in `miner.log`.

#### Building the Index
As the index is stored in a binary format, it is not pushed to the git repository.
Therefore, you need to build it for yourself locally. For this, you need to have a local
copy of the `mozilla-central` mercurial repository: https://hg.mozilla.org/mozilla-central

The command to build the index from scratch is:
```
python miner/runscript.py --extract-advisories --build-index /path/to/mozilla-central
```

This may take some time, as 300'000+ commit messages have to be checked. But you only have to build the index again if you updated the repository. The advisory extraction only has to be run if you have scraped some new advisories.
