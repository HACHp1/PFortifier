'''
configuration file
'''

import os
import shutil

# garbage collect
# on: reduce memory usage, but process speed down
# gc_switch = True
gc_switch = False

# patch generation
patch_generate = True
# patch_generate = False

# neo4j graph generation
# graph_gen = True
graph_gen = False

# neo4j password
neo4j_pass = 'password'

# use possible method summary
# use_pm_summary = False
use_pm_summary = True

# skip too many chains in pm summary mode
# skip_overdetected = False
skip_overdetected = True

# each entry only collect a sink once(to discover more sinks)
# filter_sink = False
filter_sink = True

# use cache
use_cache = False
# use_cache = True

# exclude the class whoese wakeup contains a "die()"
# exclude_die_wakeup = False
exclude_die_wakeup = True

# 查找由下列对象方法作为入口的POP链
# the entry of the pop chain, e.g. __destruct
entry_func_li = [
    # '__call',
    # '__toString',
    '__destruct',
    '__wakeup',
]

# max_pm_length: max length of the pm chain, which prevents endless loop

# max_pm_length = 3
max_pm_length = 4
# max_pm_length = 5
# max_pm_length = 6
# max_pm_length = 30

# max_normal_length: max length of the normal method chain, which prevents endless loop
# max_normal_length = 6
max_normal_length = 9

# early stop number for each entry, if found enough POP chains start with entry a, the finder will jump to find chains start with other entries
# each_entry_early_stop_num = 1
each_entry_early_stop_num = 5
# each_entry_early_stop_num = 10
# each_entry_early_stop_num = 15
# each_entry_early_stop_num = 20
# each_entry_early_stop_num = 30
# each_entry_early_stop_num = 1000
each_entry_early_stop_num = 99999

# the entry depth that early stop used. For example, if entry_depth is 2, "Class1#destruct;Class2#func" will be the "entry".
entry_depth = 1
# entry_depth = 2
# entry_depth = 3
# entry_depth = 4
# entry_depth = 5
# entry_depth = 10

# early stop number, if found enough POP chains ,the finder will stop and output the found chains
early_stop_num = 1000

# -------------------
# php_prog_root: the root directory of the php program


php_prog_root = r'/the/root/directory/of/the/php/program'
# -------------------

hunter_root = os.getcwd()

# The result dir
res_root = hunter_root + r'/result/' + php_prog_root.replace(':', "_").replace('\\', '_').replace(
    '/', '_')+'/'

# must be the absolute path, result file to store the found chains
result_file = res_root+r'pop_chains.json'

# must be the absolute path, result file to store the patch
patch_file = res_root+r'patch.json'

# result file to store the collected patch info
patch_collect_file = res_root+r'patch_collect.json'

# result file to store the pop chain entry which cannot be fixed
unable2patch_file = res_root+r'unable2patch_entry.json'

# must be the absolute path, result file to store the running information
info_file = res_root+r'info.txt'

# log info file
log_file = res_root+r'log.txt'

# python recursion limit
python_rec_depth = 10000

php_exts = set(
    # ('php', 'phtml'),
    ('php', 'phtml', 'inc'),
)  # php_exts: php extensions, e.g. .php


# cache directory

attr_func_dict_cache = hunter_root+'/cache/attr_func_dict.pkl'
class_dict_cache = hunter_root+'/cache/class_dict.pkl'
global_func_dict_cache = hunter_root+'/cache/global_func_dict.pkl'
cannot_unser_cache = hunter_root+'/cache/cannot_unser.pkl'

try:
    shutil.rmtree(res_root)
except FileNotFoundError:
    pass
os.makedirs(res_root)
