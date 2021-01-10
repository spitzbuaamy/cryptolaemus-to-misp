import argparse
import datetime
import logging
import re
import sys
from time import mktime

import feedparser
import urllib3
import yaml
from pymisp import ExpandedPyMISP, MISPEvent, MISPSighting, MISPOrganisation, MISPAttribute


class MispHandler:
    def __init__(self, config, logger):
        self.logger = logger
        MISP_KEY = config['MISP_KEY']
        MISP_URL = config['MISP_URL']
        MISP_VERIFYCERT = config['MISP_VERIFYCERT']
        self.config = config
        self.misp = ExpandedPyMISP(MISP_URL, MISP_KEY, MISP_VERIFYCERT)
        self.orgc = MISPOrganisation()
        self.orgc.name = config['MISP_ORG_NAME']
        self.orgc.id = config['MISP_ORG_ID']
        self.orgc.uuid = config['MISP_ORG_UUID']
        self.tags = config['tags']
        self.galaxy_synonyms = {}
        self.enabled_clusters = self.config['galaxies']
        self.galaxy_tags = {}
        self._init_galaxies()

    def get_event_id(self, event):
        try:
            return event['Event']['id']
        except KeyError:
            return event.id
        except TypeError:
            return event.id

    def get_attributes(self, event):
        try:
            attributes = event['Event']['Attribute']
        except KeyError:
            attributes = event.attributes
        return attributes

    def add_sigthing(self, id):
        sighting = MISPSighting()
        self.misp.add_sighting(sighting, id)

    def get_event(self, malware_type, feed_tag):
        malware_tag = "malware:" + malware_type.lower()
        res = self.misp.search(tags=[feed_tag], controller='events', pythonify=True)
        for event in res:
            for tag in event.tags:
                if tag['name'].lower() == malware_tag.lower():
                    return event
        return None

    def _init_galaxies(self):
        i = 1
        cont = True
        for cluster in self.enabled_clusters:
            self.galaxy_tags[cluster] = []

        while cont:
            g = self.misp.get_galaxy(i)
            try:
                galaxy_cluster = g['Galaxy']['name']
            except KeyError:
                cont = False
                continue
            if galaxy_cluster.lower() in self.enabled_clusters:
                elements = g['GalaxyCluster']
                for element in elements:
                    self.galaxy_tags[galaxy_cluster.lower()].append(element['tag_name'])

                    for inner_element in element['GalaxyElement']:
                        if inner_element['key'] == 'synonyms':
                            if not element['tag_name'] in self.galaxy_synonyms:
                                self.galaxy_synonyms[element['tag_name']] = []
                            self.galaxy_synonyms[element['tag_name']].append(inner_element['value'])
            i = i + 1

    def get_galaxies(self, malware_tag):
        res = []
        for cluster in self.enabled_clusters:
            for galaxy_tag in self.galaxy_tags[cluster]:
                malware = malware_tag.split(':')[1].lower().replace(" ", "")
                galaxy_value = galaxy_tag.split('"')[1].lower().replace(" ", "")
                if malware == galaxy_value:
                    res.append(galaxy_tag)
                    break
                else:
                    if galaxy_tag in self.galaxy_synonyms:
                        for synonym in self.galaxy_synonyms[galaxy_tag]:
                            galaxy_value = synonym.lower().replace(" ", "")
                            if malware == galaxy_value:
                                res.append(galaxy_tag)
                                break
        return res

    def get_file_taxonomy(self, ft):
        if ft == 'exe':
            return 'file-type:type="peexe"'
        elif ft == 'dll':
            return 'file-type:type="pedll"'
        elif ft == 'apk':
            return 'file-type:type="android"'
        else:
            return 'file-type:type="' + ft + '"'
        return ''

    def new_misp_event(self, malware_type, feed_tag, event_info, additional_tags=[]):
        malware_tag = "malware:" + malware_type.lower()
        misp_event_obj = MISPEvent()
        misp_event_obj.info = event_info
        misp_event_obj.add_tag(feed_tag)
        if len(malware_tag) > 0:
            misp_event_obj.add_tag(malware_tag.lower())
        for tag in self.config['tags']:
            misp_event_obj.add_tag(tag)
        for tag in additional_tags:
            misp_event_obj.add_tag(tag)
        misp_event_obj.orgc = self.orgc

        galaxies = self.get_galaxies(malware_tag)
        for galaxy in galaxies:
            misp_event_obj.add_tag(galaxy)
        misp_event = self.misp.add_event(misp_event_obj, pythonify=True)
        return misp_event


class CryptolaemusImporter:
    def __init__(self, logger, config):
        self.logger = logger
        self.config = config
        url = 'https://paste.cryptolaemus.com/feed.xml'
        self.iocfeed = feedparser.parse(url)
        self.mh = MispHandler(config, logger)
        self.feed_tag = 'feed:cryptolaemus'
        self.first_seen = ''
        self.last_ioc = config['LAST_IMPORTED_IOC']
        self.import_hashes = config['IMPORT_HASHES']
        self.source = ''
        self.epoch_tag = None
        self.killchain_tax = None
        self.first_ioc = None
        self.finished = False

    def check_attr(self, value):
        for attribute in self.event.attributes:
            if attribute.value == value:
                if attribute.type in self.config['types_sightings']:
                    self.mh.add_sigthing(attribute.id)
                return False
        return True

    def add_link(self, link):
        attr = MISPAttribute()
        attr.type = "link"
        attr.value = link
        attr.comment = "IOC Source"
        self.source = link
        self.mh.misp.add_attribute(self.event.id, attr)

    def add_url(self, url):
        attr = MISPAttribute()
        attr.type = "url"
        attr.value = url
        attr.first_seen = self.first_seen
        attr.comment = self.source
        if self.killchain_tax is not None:
            attr.add_tag(self.killchain_tax)
        if self.epoch_tag is not None:
            attr.add_tag(self.epoch_tag)
        self.mh.misp.add_attribute(self.event.id, attr)

    def add_generic(self, hash, type):
        attr = MISPAttribute()
        attr.type = type
        attr.value = hash
        attr.first_seen = self.first_seen
        attr.comment = self.source
        if self.killchain_tax is not None:
            attr.add_tag(self.killchain_tax)
        if self.epoch_tag is not None:
            attr.add_tag(self.epoch_tag)
        self.mh.misp.add_attribute(self.event.id, attr)

    def get_ioc_info(self, ioc):
        if "epoch-1" in ioc or "Epoch 1" in ioc:
            self.epoch_tag = 'emotet:epoch="1"'
        elif "epoch-2" in ioc or "Epoch 2" in ioc:
            self.epoch_tag = 'emotet:epoch="2"'
        elif "epoch-3" in ioc or "Epoch 3" in ioc:
            self.epoch_tag = 'emotet:epoch="3"'
        if "payloads-by-document" in ioc:
            self.killchain_tax = "kill-chain:Delivery"
        elif "documentdownloader-links" in ioc:
            self.killchain_tax = "kill-chain:Weaponization"

        if "Creation Time" in ioc:
            found = re.search('\d{4}:\d{2}:\d{2}\s+\d+:\d+\d+', ioc)
            if found is not None:
                self.first_seen = datetime.datetime.strptime(found[0], '%Y:%m:%d %H:%M')

        if 'id="end"' in ioc or "Credits and Notes Section" in ioc or 'credits-and-notes-section' in ioc or 'current-epoch-3-rsa-public-key' in ioc:
            self.next_link = True
            self.epoch_tag = ""
            self.killchain_tax = ""
            return 'end'
        if ioc.startswith('http') and 'cryptolaemus.com/' in ioc:
            return None
        if ioc.startswith("http") or ioc.startswith("hxxp"):
            return "url"
        match_ip = re.match('\d+\.\d+\.\d+\.\d+:\d+', ioc)
        if match_ip is not None:
            return "ip-dst|port"
        match = re.match('[0-9a-f]{64}', ioc)
        if match is None:
            self.logger.info("No Type Found: " + ioc)
            return None
        else:
            return "sha256"

    def add_attribute(self, ioc):
        attributes = ioc.split('<code>')
        for attr in attributes:
            if self.check_attr(attr):
                if attr == self.last_ioc:
                    self.finished = True
                type = self.get_ioc_info(attr)
                if type is None:
                    return
                if self.first_ioc is None:
                    self.first_ioc = attr
                if type == 'url':
                    self.add_url(attr)
                elif type == 'sha256' and self.import_hashes:
                    self.add_generic(attr, type)
                elif type == "ip-dst|port":
                    self.killchain_tax = "kill-chain:Command and Control"
                    self.add_generic(attr.replace(':', '|'), type)
                elif type == "end" or self.finished:
                    break

    def import_feed(self):
        event = self.mh.get_event(malware_type='Emotet', feed_tag=self.feed_tag)
        if event is None:
            event_info = "Emotet IOCs by Cryptolaemus"
            event = self.mh.new_misp_event('Emotet', self.feed_tag, event_info)
        self.event = event

        for entry in self.iocfeed.entries:
            if not self.check_attr(entry['link']):
                continue
            self.add_link(entry['link'])
            self.first_seen = datetime.datetime.fromtimestamp(mktime(entry['published_parsed']))
            for iocs in entry['content']:
                for ioc in iocs['value'].split('\n'):
                    self.next_link = False
                    self.add_attribute(str(ioc))
                    if self.next_link:
                        break
                    if self.finished:
                        break
                if self.finished:
                    break
        if self.finished:
            self.config['LAST_IMPORTED_IOC'] = self.first_ioc
            self.mh.misp.publish(self.event)


def init_logger(level):
    logger = logging.getLogger('abusech-to-misp')

    handler = logging.StreamHandler(sys.stdout)
    level = logging.getLevelName(level)
    handler.setLevel(level)

    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger


def load_config(config_file, logger):
    try:
        with open(config_file) as f:
            config = yaml.load(f, Loader=yaml.FullLoader)
    except Exception as e:
        logger.error("Error while loadig Config")
        logger.error(e)
    return config


def write_config(config_file, logger, config):
    try:
        with open(config_file, "w") as f:
            config = yaml.dump(config, f)
    except Exception as e:
        logger.error("Error while loadig Config")
        logger.error(e)


if __name__ == '__main__':
    urllib3.disable_warnings()
    parser = argparse.ArgumentParser(description='Sync Cryptolaemus IOCs to MISP')
    parser.add_argument('-c', '--config', required=True, help='Config File')
    parser.add_argument('-l', '--loglevel', required=False, help='Set Log Level',
                        choices=['DEBUG', "INFO", "WARNING", "ERROR", 'CRITICAL'], default='DEBUG')

    args = parser.parse_args()
    logger = init_logger(args.loglevel)

    config = load_config(args.config, logger)

    if 'log_level' in config:
        logger.setLevel(logging.getLevelName(config['log_level']))

    ci = CryptolaemusImporter(logger, config)
    ci.import_feed()
    write_config(args.config, logger, ci.config)
