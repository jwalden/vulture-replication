# Condor (vulture-replication)
Replication study of the "Vulture" paper "Predicting Vulnerable Software Components" (CCS'07).

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
python condor/miner/runscript.py
```

There is also a basic help for the script:
```
python condor/miner/runscript.py --help
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
python condor/miner/runscript.py --extract-advisories --build-commit-index /path/to/mozilla-central
```

This may take some time (~ 20 minutes), as 300'000+ commit messages have to be checked. But you only have to build the index again if you updated the repository. The advisory extraction only has to be run if you have scraped some new advisories. This index mainly exists for convenience. Without this intermediate step, building the file index from scratch would take about 40 minutes.


The structure of the index is as follows:
```
{
    u'996715': [('185152', '9d8a5c8d8328af315768f1fb50b5a1fc3ab01d4e', 'bug 996715: Remove the code that bails when determining if the second instruction in a chunk is a branch. (r=dougc)')],
    u'996883': [('179313', 'd8300867f3f219a3d183ee0577d548d04f802d8c', 'Land bug 996883. r=mjrosenb')],
    u'997795': [('179215', 'ba276673a564f5906115959a1823250123f8ca4a', 'Bug 997795 - Cleanup decodings. r=dkeeler')]
}
```
The key is the vulnerability-related bug number and the value is a list of affected commits `(commit number, node, commit message)`.


#### Building the File Index
This index contains the modified files for each commit. It is also stored in a binary format and not pushed to the git repository. Due to the nature of the `hglib` module, this also takes about 20 minutes to run.

```
python condor/miner/runscript.py --build-file-index /path/to/mozilla-central
```

The structure of the index is as follows:
```
{
    u'995817': [('M', 'js/src/jit/MIR.h'),
                ('M', 'js/src/jit/RangeAnalysis.cpp'),
                ('M', 'js/src/jit/arm/CodeGenerator-arm.cpp'),
                ('M', 'js/src/jit/shared/CodeGenerator-x86-shared.cpp')],
    u'996536': [('M', 'js/src/jsinfer.cpp')],
    u'996715': [('M', 'js/src/jit/shared/IonAssemblerBufferWithConstantPools.h')]
}
```
The key is again the vulnerability-related bug number, but the value is a list of modified files (`'M'`) as returned by `hglib.status`.


#### Extracting Components
This is the third index which fetches all the `.c`, `.cpp` and `.h` files from the repository and looks at the import statements. Building of this index is rather quick, it takes about 10-20 seconds.


The structure of the index is as follows:
```
{
    'xpcAccessibleHyperLink': {'files': [('/home/hklauser/school/semester-6/BA/repos/mozilla-central/accessible/xpcom',
                                          'xpcAccessibleHyperLink.cpp'),
                                         ('/home/hklauser/school/semester-6/BA/repos/mozilla-central/accessible/xpcom',
                                          'xpcAccessibleHyperLink.h')],
                               'includes': set(['Accessible-inl.h',
                                                'nsIAccessibleHyperLink.h',
                                                'nsNetUtil.h',
                                                'xpcAccessibleDocument.h'])},
    'xpcAccessibleHyperText': {'files': [('/home/hklauser/school/semester-6/BA/repos/mozilla-central/accessible/xpcom',
                                          'xpcAccessibleHyperText.cpp'),
                                         ('/home/hklauser/school/semester-6/BA/repos/mozilla-central/accessible/xpcom',
                                          'xpcAccessibleHyperText.h')],
                               'includes': set(['Accessible-inl.h',
                                                'HyperTextAccessible-inl.h',
                                                'HyperTextAccessible.h',
                                                'TextRange.h',
                                                'nsIAccessibleEditableText.h',
                                                'nsIAccessibleHyperText.h',
                                                'nsIAccessibleText.h',
                                                'nsIMutableArray.h',
                                                'nsIPersistentProperties2.h',
                                                'xpcAccessibleDocument.h',
                                                'xpcAccessibleGeneric.h',
                                                'xpcAccessibleHyperText.h',
                                                'xpcAccessibleTextRange.h'])}
}
```
The key is the component name. The value is again a dict consisting of two key/value pairs:
- `files`: A list of files which define that component (tuple of path and filename)
- `includes`: A set of all the includes of that component
