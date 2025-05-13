from POPChainHunter.utils import *
from POPChainHunter.core import ASTExecutor
import shutil

import argparse

from POPAutoPatch.AutoPatch import *
import time


parser = make_parser()
testphpfile = open('phpcode/nor_test.php', encoding='utf8').read()
lexer.lexer.begin('INITIAL')
lexer.lineno = 1
vast = parser.parse(testphpfile, lexer=lexer)

myExecutor = ASTExecutor()

new_key = random_string()  # 生成初始key
pop_dict[new_key] = []  # 初始化

pop_dict[new_key].append(
    ['', '', ''])  # 记录入口

myExecutor.execute_ast(vast, '', new_key, {})
