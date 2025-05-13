'''
POP chain searching with payload generate
'''

from POPChainHunter.utils import *
from POPChainHunter.core import ASTExecutor, cg_collector
import argparse
import json

# 获取命令行中的设置，否则使用config中的设置

parser = argparse.ArgumentParser()

parser.add_argument("-root", default=php_prog_root,
                    help="The root directory of the php program", type=str)
args = parser.parse_args()

php_prog_root = args.root

print('[message] Generating AST...')

os.chdir(php_prog_root)  # 进入程序根目录

parser = make_parser()
lexer.lexer.begin('INITIAL')
lexer.lineno = 1

if __name__ == '__main__':

    print('[message] Setting attributions...')

    # 预先的数据结构维护

    namespace = ''
    use_list = {}

    dynamic_class_set_attr()  # 解析所有php文件

    print('[message] Start searching POP chains...')

    for func in entry_func_li:

        # 去掉不存在的对象方法
        if func not in attr_func_dict:
            continue

        for vclass in attr_func_dict[func]:  # 查找入口类

            new_key = random_string()  # 生成初始key

            root = ControllableInstance(vclass)  # 根对象
            root.key = new_key
            local_var = LocalVarDict({
                'this': root
            })

            called_method = class_dict[vclass][func]

            pop_dict[new_key] = POPInfo(root)  # 记录POP链信息
            pop_dict[new_key].possibleInfo.append(func+':')
            pop_dict[new_key].normalInfo.append(vclass+'#'+func)
            pop_dict[new_key].callsiteInfo.append(
                [called_method.sourcefile, called_method.lineno])
            condition_stack.append(set()) # 最外层的条件栈
            cond_stack_depth.append(len(condition_stack))
            if '__wakeup' in class_dict[vclass]:
                pop_dict[new_key].wakeupExist = True

            # 尝试获取use语句列表
            if hasattr(called_method, 'use_list'):
                use_list = called_method.use_list
            else:
                use_list = {}
            myExecutor = ASTExecutor(new_key, namespace, local_var, use_list)

            myExecutor.execute_ast(called_method)  # 执行ast

    print('[message] POP chains searching progress ends!')
    print('[message] POP chains have been saved!')

    # neo4j graph generation
    if graph_gen:
        print('[message] Call Graph generating...')
        cg_collector.save2neo4j()
        print('[message] Call Graph generation finished!')

    # patch info collection
    if patch_generate:
        with open(patch_collect_file, 'w') as fw:
            fw.write(json.dumps(list(patch_collect)))
        with open(unable2patch_file, 'w') as fw:
            fw.write(json.dumps(list(unable2patch_entry)))

    end_time = time.time()
    # info log
    info_log(end_time)
