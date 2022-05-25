import os
import platform
import stat
import sys
import subprocess
import json
import splunk.Intersplunk as intersplunk
import recommendation_task.recommendation_consts as const
import tempfile
from splunklib.six.moves import reload_module
from splunklib.six import PY2,PY3
import app_aws_bin.utils.app_util as util
logger = util.get_logger()

COMPATIBLE_SA_VERSIONS = ['1.1','1.2']
AWS_SA_SUFFIX = '_awsapp'

def execute_ml_process(process_py_name, json_arg, session_key):
    """Execute the current Python script using the Anaconda Python
    interpreter included with Splunk_SA_Scientific_Python.

    After executing this function, you can safely import the Python
    libraries included in Splunk_SA_Scientific_Python (e.g. numpy).
    """

    if 'Continuum' in sys.version:
        fix_sys_path()
        reload_module(os)
        reload_module(platform)
        reload_module(stat)
        reload_module(sys)
        reload_module(subprocess)
        return

    supported_systems = {
        ('Linux', 'i386'): 'linux_x86',
        ('Linux', 'x86_64'): 'linux_x86_64',
        ('Darwin', 'x86_64'): 'darwin_x86_64',
        ('Windows', 'AMD64'): 'windows_x86_64'
    }

    system = (platform.system(), platform.machine())
    if system not in supported_systems:
        raise Exception('Platform not supported by Splunk_SA_Scientific_Python: %s %s' % (system))

    sa_path = os.path.join(os.environ['SPLUNK_HOME'], 'etc', 'apps', 'Splunk_SA_Scientific_Python_%s' % (supported_systems[system]))

    sa_name = 'Splunk_SA_Scientific_Python_%s' % (supported_systems[system])

    if not os.path.isdir(sa_path):
        raise Exception('Failed to find Splunk_SA_Scientific_Python_%s' % (supported_systems[system]))

    sa_ver = util.get_option_from_conf(session_key, "app", "launcher", "version", sa_name)

    if sa_ver not in COMPATIBLE_SA_VERSIONS:
        sa_path += AWS_SA_SUFFIX
        if not os.path.isdir(sa_path):
            raise Exception('Failed to find Splunk_SA_Scientific_Python_%s%s' % (supported_systems[system],AWS_SA_SUFFIX))

    system_path = os.path.join(sa_path, 'bin', '%s' % (supported_systems[system]))

    if system[0] == 'Windows':
        python_path = os.path.join(system_path, 'python.exe')
    else:
        python_path = os.path.join(system_path, 'bin', 'python')

    # Ensure that execute bit is set on .../bin/python
    if system[0] != 'Windows':
        mode = os.stat(python_path).st_mode
        os.chmod(python_path, mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    ml_py_path = os.path.join(const.APP_BIN_PATH, 'machine_learning_mod', process_py_name)

    # use file to record json arguments, or it may cause OS Error: Argument list too long
    arg_file_path = os.path.join(tempfile.gettempdir(), process_py_name.split('.')[0] + '.arguments')
    arg_file = open(arg_file_path, 'w')
    arg_file.write(json.dumps(json_arg))
    arg_file.close()

    try:
        if PY3:
            logger.info("Current Python version: 3.7")
            ml_process = subprocess.Popen([python_path, ml_py_path, process_py_name.split('.')[0]], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        elif PY2:
            logger.info("Current Python version: 2.7")
            ml_process = subprocess.Popen([python_path, ml_py_path, process_py_name.split('.')[0]], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        (stdoutput, erroutput) = ml_process.communicate()
    except Exception as e:
        logger.exception(e)
        
    logger.info('Machine Learning Results: %s' % stdoutput)
    logger.info('Machine Learning Errors: %s' % erroutput)

    return json.loads(stdoutput)


def fix_sys_path():
    # Update sys.path to move Splunk's PYTHONPATH to the end.
    pp = os.environ.get('PYTHONPATH', None)
    if not pp: return
    for spp in pp.split(os.pathsep):
        try:
            sys.path.remove(spp)
            sys.path.append(spp)
        except: pass
