import os
import re
import matplotlib.pyplot as plt

from matplotlib.ticker import ScalarFormatter
from itertools import chain
from bs4 import BeautifulSoup
try:
    from urllib.parse import urlparse, unquote
except ImportError:
    from urlparse import urlparse
    from urllib import unquote

from lib.core import serialize
from lib.miner.mozilla import MozillaMiner


components = serialize.read('data/mozilla/components-multifeature-18.05.pickle')


mfsas = {}
bugs = []

def _parse_advisory(path):
    with open(path, 'r') as f:
        content = f.read()
    bs = BeautifulSoup(content, 'html5lib')
    body = bs.find('div', attrs={'itemprop': 'articleBody'})

    bugs = []
    for link in body.find_all('a'):
        href = link.attrs['href']
        query = unquote(urlparse(href).query).replace('\n', '')
        ids = MozillaMiner.BUG_PATTERN.findall(query)
        if len(ids) > 0:
            bugs.extend(ids[0][1].split(','))

    bugs.extend(bugs)
    return bugs

advisories = os.listdir('data/mozilla/advisories')
for i, advisory in enumerate(advisories):
    bids = _parse_advisory(os.path.join('data/mozilla/advisories', advisory))
    for bid in bids:
        mfsas[bid] = advisory
    bugs.extend(bids)


# General Stats
print('Distinct bug numbers:                            {}'.format(len(set(bugs))))
print('Distinct bug numbers in the component index:     {}'.format(len(set(
    chain.from_iterable(c['bugs'].keys() for c in components['index'].values())))))
print('')


# Ranking of vulnerable components
ranking = []

for component, data in components['index'].items():
    bugs = data['bugs'].keys()
    nmfsas = len(set([mfsas[bug] for bug in bugs]))
    ranking.append(
        (component, nmfsas, len(bugs), data['files'])
    )

print('Top 10 most vulnerable components:')
print('')
print('{:>30} {:>10} {:>15}'.format('Component', 'MFSAs', 'Bug Reports'))
print('')
for component in sorted(ranking, key=lambda x: x[1], reverse=True)[:10]:
    print('{:>30} {:>10} {:>15}'.format(component[0], component[1], component[2]))


# Distribution and Histogram
dist_mfsa = {}
dist_bugs = {}
for c in ranking:
    if c[1] in dist_mfsa.keys():
        dist_mfsa[c[1]] += 1
    else:
        dist_mfsa[c[1]] = 1
    if c[2] in dist_bugs.keys():
        dist_bugs[c[2]] += 1
    else:
        dist_bugs[c[2]] = 1

mfsa_x = []
mfsa_y = []
for n_mfsa, n_comp in dist_mfsa.items():
    if n_mfsa != 0:
        mfsa_x.append(n_mfsa)
        mfsa_y.append(n_comp)

bugs_x = []
bugs_y = []
for n_bugs, n_comp in dist_bugs.items():
    if n_bugs != 0:
        bugs_x.append(n_bugs)
        bugs_y.append(n_comp)

fig = plt.figure()
ax1 = fig.add_subplot(1, 2, 1)
ax1.bar(mfsa_x, mfsa_y)
ax1.set_yscale('log')
ax1.yaxis.set_major_formatter(ScalarFormatter())
plt.xlabel('Number of MFSAs')
plt.ylabel('Number of Components')
plt.title('Distribution of MFSAs')
plt.xticks([tick for i, tick in enumerate(mfsa_x) if i % 2 == 0 or tick == 27 or tick >= 33])
ax2 = fig.add_subplot(1, 2, 2)
ax2.bar(bugs_x, bugs_y)
ax2.set_yscale('log')
ax2.yaxis.set_major_formatter(ScalarFormatter())
plt.xlabel('Number of Bug Reports')
plt.ylabel('Number of Components')
plt.title('Distribution of Bug Reports')
plt.xticks([tick for i, tick in enumerate(bugs_x) if i % 2 == 0 or tick == 33])
plt.show()