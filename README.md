# vulture-replication
Replication study of the "Vulture" paper "Predicting Vulnerable Software Components" (CCS'07)

## Setup
This project makes use of Python 2.7, although Python 3.4+ should work as well. You can either use Anaconda or set up a virtual environment.

### Using virtualenv
First, create a virtual environment and activate it:

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

Then, install all the dependencies in the virtual environment:
```
pip install -e .
```

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
python miner/runscript.py --help
```

**IMPORTANT:** Please note that scraping the individual advisories will send 1000+ HTTP requests to Mozilla in a short amount of time. Because of this, the individual advisory pages are stored in data/miner/advisories/.

#### Log File
The output of the script is quite basic. If you want to see more detailed output, you can
observe the log output in `miner.log`.

#### Building the Commit Index
As the index is stored in a binary format, it is not pushed to the git repository.
Therefore, you need to build it for yourself locally. For this, you need to have a local
copy of the `mozilla-central` mercurial repository: https://hg.mozilla.org/mozilla-central

The command to build the index from scratch is:
```
python miner/runscript.py --extract-advisories --build-commit-index /path/to/mozilla-central
```

This may take some time, as 300'000+ commit messages have to be checked. But you only have to build the index again if you updated the repository. The advisory extraction only has to be run if you have scraped some new advisories.
