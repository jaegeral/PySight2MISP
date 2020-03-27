import configparser
import logging


# Initialize the config parser
config = configparser.RawConfigParser()

# Read the config file and set config values
config.read('config.cfg')

LOG_LEVEL = config.get('general', 'log_level')
use_threading = config.getboolean('general', 'use_threading')
number_threads = config.getint('general', 'number_threads')

isight_url = config.get('isight', 'isight_url')
isight_priv_key = config.get('isight', 'isight_priv_key')
isight_pub_key = config.get('isight', 'isight_pub_key')
isight_last_hours = config.getint('isight', 'last_hours')

misp_url = config.get('MISP', 'misp_url')
misp_key = config.get('MISP', 'misp_key')
misp_verifycert = config.getboolean('MISP', 'misp_verifycert')


USE_ISIGHT_PROXY = config.getboolean('proxy', 'use_isight_proxy')
USE_MISP_PROXY = config.getboolean('proxy', 'use_misp_proxy')
if USE_ISIGHT_PROXY or USE_MISP_PROXY:
    PROXY_HOST = config.get('proxy', 'host')
    PROXY_PORT = config.get('proxy', 'port')
    PROXY_PROTOCOL = config.get('proxy', 'protocol')
    proxy = config.get('proxy', 'full')
    proxy_address = proxy

debug_mode = False

# Create a logger.
logger = logging.getLogger(__name__)
# Set the loglevel, also for imported modules.
if LOG_LEVEL.upper() == 'DEBUG':
    logger.setLevel(logging.DEBUG)
    logging.getLogger('pymisp').setLevel(logging.DEBUG)
    logging.getLogger('urllib3').setLevel(logging.DEBUG)
    debug_mode = True
elif LOG_LEVEL.upper() == 'INFO':
    logger.setLevel(logging.INFO)
    logging.getLogger('pymisp').setLevel(logging.INFO)
    logging.getLogger('urllib3').setLevel(logging.INFO)
elif LOG_LEVEL.upper() == 'WARNING':
    logger.setLevel(logging.WARNING)
    logging.getLogger('pymisp').setLevel(logging.WARNING)
    logging.getLogger('urllib3').setLevel(logging.WARNING)
elif LOG_LEVEL.upper() == 'ERROR':
    logger.setLevel(logging.ERROR)
    logging.getLogger('pymisp').setLevel(logging.ERROR)
    logging.getLogger('urllib3').setLevel(logging.ERROR)
elif LOG_LEVEL.upper() == 'CRITICAL':
    logger.setLevel(logging.CRITICAL)
    logging.getLogger('pymisp').setLevel(logging.CRITICAL)
    logging.getLogger('urllib3').setLevel(logging.CRITICAL)
else:
    print('Invalid logging level "%s". Using default level WARNING.' % LOG_LEVEL)
    logger.setLevel(logging.WARNING)
    logging.getLogger('pymisp').setLevel(logging.WARNING)
    logging.getLogger('urllib3').setLevel(logging.WARNING)

# Create a file handler and log there, too, in addition to the console.
log_file = logging.FileHandler('output.log')
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
log_file.setFormatter(formatter)
logger.addHandler(log_file)
