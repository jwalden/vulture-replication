import json


class Config:

    def __init__(self, path='condor/config.json'):
        with open(path, 'r') as f:
            self.config = json.load(f)

    @property
    def mfsa_overview(self):
        return self._miner_settings['files']['mfsa_overview']

    @property
    def mfsa_dir(self):
        return self._miner_settings['directories']['mfsa_pages']

    @property
    def bugs(self):
        return self._miner_settings['files']['extracted_bugs']

    @property
    def commit_index(self):
        return self._miner_settings['files']['commit_index']

    @property
    def file_index(self):
        return self._miner_settings['files']['file_index']

    @property
    def components(self):
        return self._miner_settings['files']['components']

    @property
    def dataset(self):
        return self._miner_settings['files']['dataset']

    @property
    def _miner_settings(self):
        return self.config['miner']
