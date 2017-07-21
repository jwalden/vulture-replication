# Condor (vulture-replication)
Replication study of the "Vulture" paper "Predicting Vulnerable Software Components" (CCS'07).

## Setup
This project makes use of Python 2.7, although Python 3.4+ should work as well.

### Using virtualenv
#### Python 2.7
First, create a virtual environment in the folder `venv`:
```
virtualenv venv
```

Activate the environment:
```
source venv/bin/activate
```

#### Python 3.4+
Same for Python 3, with the exception of the different command to create the virtual environment:
```
python3 -m venv venv
```

Activation stays the same:
```
source venv/bin/activate
```

#### Install Dependencies
When the virtual environment is activated, you can install all the dependencies:
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
There is a basic run script for the miner application, located in the root directory. It has to be run from the project root directory:
```
python cli.py
```

There is also a help for the script:
```
python cli.py --help
```

For most arguments, both the source and the path to the repository have to be specified, for example:
```
python cli.py -s mozilla -r /path/to/mozilla-central --checkout-head
```


#### Scraping
Scraping and the generation of the preliminary indices is source (project) specific and requires an appropriate implementation. The time required for the generation of the preliminary indices is source dependent, but will usually take about 10 minutes. 

Please note that scraping the individual advisories will send a lot of HTTP requests in a short amount of time. Because of this, the individual advisory pages are stored in data.

##### Implementations
Currently the following sources have been implemented.
- Mozilla: mozilla-central

#### Building the Component Index
Building the component index requires the preliminary indices. It is the most time intensive task and will take about 20 minutes when including the include history. Please be aware that the component index can't be shared accross systems, as it contains the path to the local copy of the source repository.

#### Building the Data Set
Building the data set requires a component index and takes about 30 seconds.

#### Log File
The output of the script is quite basic. If you want to see more detailed output, you can
observe the log output in `condor.log`.
