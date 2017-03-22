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
There is a basic run script for the miner application, located in the miner directory. It has to be run from the project root directory:
```
python condor-cli.py
```

There is also a basic help for the script:
```
python condor-cli.py --help
```

**IMPORTANT:** Please note that scraping the individual advisories will send 1000+ HTTP requests to Mozilla in a short amount of time. Because of this, the individual advisory pages are stored in data/miner/advisories/.

#### Log File
The output of the script is quite basic. If you want to see more detailed output, you can
observe the log output in `condor.log`.

#### Mercurial Repository
For some of the following commands, you need to have a local copy of the `mozilla-central` mercurial repository: https://hg.mozilla.org/mozilla-central

You will need to specify the path to your copy with the `--repo` or `-r` argument, e.g. `--repo /home/user/mozilla-central`. If you fail to provide this argument when it is required, the CLI script will abort and tell you so.

You can chain as many arguments as you like, but you only have to specify the repository path once.

#### Building the entire Data Set
If you want to build the entire data set from scratch, you only have to execute a single command.
```
python condor-cli.py --build-complete --repo /path/to/mozilla-central
```
##### Please Note:
- This will not scrape the advisory overview nor the individual advisory pages.
- This usually takes 30+ minutes, depending on your hardware.

#### Scrape Advisories and Extract the Advisory Bug Numbers
```
python condor-cli.py --scrape-overview
python condor-cli.py --scrape-advisories
python condor-cli.py --extract-advisories
```

#### Building the Commit Index
The commit index is an intermediate index which maps vulnerability-related bug numbers to commits (i.e. revision numbers, node hashes and commit messages) in the mercurial repository. It mainly exists for convenience, as it takes about 20 minutes to build. This way, the following data structures can be built without having to wait 20 minutes each time.

As the index is stored in a binary format, it is not pushed to the git repository. Therefore, you need to build it for yourself locally the first time and whenever there has been an update to the repository and/or the advisories.

The command to build the index from scratch is:
```
python condor-cli.py --build-commit-index --repo /path/to/mozilla-central
```

This may take some time (~ 20 minutes), as 300'000+ commit messages have to be checked against multiple regular expressions.


The structure of the index is as follows:
```
{
  u'996715': [('185152', '9d8a5c8d8328af315768f1fb50b5a1fc3ab01d4e', 'bug 996715: Remove the code that bails when determining if the second instruction in a chunk is a branch. (r=dougc)')],
  u'996883': [('179313', 'd8300867f3f219a3d183ee0577d548d04f802d8c', 'Land bug 996883. r=mjrosenb')],
  u'997795': [('179215', 'ba276673a564f5906115959a1823250123f8ca4a', 'Bug 997795 - Cleanup decodings. r=dkeeler')]
}
```
The key is the vulnerability-related bug number and the value is a list of affected commits `(commit number, node hash, commit message)`.


#### Building the File Index
This index contains the modified files for each commit. It is also stored in a binary format and not pushed to the git repository. Due to the rather slow nature of the `hglib` module, this takes about 10 minutes to run.

```
python condor-cli.py --build-file-index --repo /path/to/mozilla-central
```

The structure of the index is as follows:
```
{
  u'992968': {'178813': [('M', 'js/src/jit/CodeGenerator.cpp'),
                         ('M', 'js/src/jit/shared/CodeGenerator-shared.h')]},
  u'993546': {'178550': [('M', 'extensions/spellcheck/hunspell/src/hunspell_alloc_hooks.h'),
                         ('M', 'extensions/spellcheck/hunspell/src/mozHunspell.cpp'),
                         ('M', 'extensions/spellcheck/hunspell/src/mozHunspell.h'),
                         ('M', 'gfx/thebes/gfxAndroidPlatform.cpp'),
                         ('M', 'xpcom/base/nsIMemoryReporter.idl'),
                         ('M', 'xpcom/build/nsXPComInit.cpp')]},
}
```
The key is again the vulnerability-related bug number. The value is another dict with the revision number as key and a list of files as value. The list of files contains the tuples as returned by the `status` function of a `hglib` client, i.e. `(code, file)`.


#### Extracting Components
This is the third index which fetches all the `.c`, `.cpp` and `.h` files from the repository and looks at the import statements. Building of this index is rather quick, it takes about 10-20 seconds.


The structure of the index is as follows:
```
{
  'voip_metric': {'files': [('/home/hklauser/school/semester-6/BA/repos/mozilla-central/media/webrtc/trunk/webrtc/modules/rtp_rtcp/source/rtcp_packet', 'voip_metric.h')],
                  'includes': set(['webrtc/base/basictypes.h', 'webrtc/modules/include/module_common_types.h']),
                  'vulncount': 0},
  'vorbis_analysis': {'files': [('/home/hklauser/school/semester-6/BA/repos/mozilla-central/media/libvorbis/lib', 'vorbis_analysis.c')],
                      'includes': set(['codec_internal.h',
                                       'math.h',
                                       'misc.h',
                                       'ogg/ogg.h',
                                       'os.h',
                                       'registry.h',
                                       'scales.h',
                                       'stdio.h',
                                       'string.h',
                                       'vorbis/codec.h']),
                      'vulncount': 2},
}
```
The key is the component name. The value is again a dict consisting of three key/value pairs:
- `files`: A list of files which define that component (tuple of path and filename)
- `includes`: A set of all the includes of that component
- `vulncount`: The number of vulnerability-related bug reports for this component


#### Building the Data Set (Feature Matrix)
The components data structure contains all the information needed to build the feature matrix:

```
python condor-cli.py --build-dataset
```

This will store the data set in a sparse format. It can be read again with the `from_sparse` function in `condor/miner/dataset.py`. It returns a tuple: `(numpy feature matrix, row names, column names)`. The last column in the feature matrix contains the targets, i.e. the vulnerability vector.
