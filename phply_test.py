from phply import phpast

from phply.phpparse import make_parser
from phply.phplex import lexer

# from POPChainHunter.utils import *

import os


# phpfile = 'phpcode/null_par.php'
# phpfile = 'phpcode/test_class.php'
# phpfile = 'phpcode/double_q.php'
# phpfile = 'phpcode/anon_func.php'
# phpfile='phpcode/splat_oper.php'
# phpfile = 'phpcode/short_tag.php'
# phpfile = 'phpcode/include_test.php'
# phpfile = 'phpcode/namespace.php'
# phpfile = 'phpcode/helloworld/unser_hellowd.php'
# phpfile = 'phpcode/pop_master/class.php'
# phpfile = 'phpcode/function_return_type.php'
# phpfile = 'phpcode/use_type.php'
# phpfile = 'phpcode/multi_use.php'
# phpfile = 'phpcode/namespace2.php'
# phpfile = 'phpcode/abstr_itf.php'
# phpfile = 'phpcode/autoload.php'
# phpfile = 'phpcode/as_test.php'
# phpfile = 'phpcode/flat_code.php'
# phpfile = 'phpcode/obj_arr.php'
# phpfile = 'phpcode/var_static.php'
phpfile = 'phpcode/test.php'

# phpfile = r'phpcode\laravel\vendor\league\commonmark\src\Extension\CommonMark\Parser\Block\HeadingParser.php'


parser = make_parser()
testphpfile = open(phpfile, encoding='utf8').read()
vast = parser.parse(testphpfile, lexer=lexer)

exit()
