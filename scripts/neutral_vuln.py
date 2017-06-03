from lib.core.serialize import read


first = read('plot/components_2015-03-01.pickle')['index']
second = read('plot/components_2017-03-09.pickle')['index']

neutral = []
for c, d in first.items():
    if len(d['bugs'].keys()) == 0:
        neutral.append(c)
print('as of 2015-03:')
print('neutral:        {}'.format(len(neutral)))
print('')

nowvuln = []
notoccur = []
stillneutral = []
for c in neutral:
    if c in second.keys():
        d = second[c]
        if len(d['bugs'].keys()) == 0:
            stillneutral.append(c)
        else:
            nowvuln.append(c)
    else:
        notoccur.append(c)
print('as of 2017-03:')
print('now vulnerable: {}'.format(len(nowvuln)))
print('still neutral:  {}'.format(len(stillneutral)))
print('removed / lost: {}'.format(len(notoccur)))
