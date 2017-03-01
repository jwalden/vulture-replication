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
