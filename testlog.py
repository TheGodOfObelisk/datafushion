# this is a simple example
import logging
import time
# define the log file, file mode and logging level
logging.basicConfig(filename='keepwriting.log', filemode="a", level=logging.DEBUG,format='%(asctime)s - %(levelname)s - %(message)s')
logging.debug('This message should go to the log file')
logging.info('So should this')
logging.warning('And this, too')

time.sleep(15)
logging.warning('I am late')