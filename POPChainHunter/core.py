'''
POP Chain Hunter
'''

import copy
import gc
import json
from POPChainHunter.utils import *
from POPChainHunter.BuiltinFuncs import builtin_func
from POPChainHunter.PayloadGen import PayloadGen
from POPAutoPatch.AutoPatch import AutoPatch
from GraphCollector.GraphCollector import GraphCollector
import traceback


# patch生成
if patch_generate:
    autoPatch = AutoPatch()
else:
    autoPatch = None

# 调用图收集器
if graph_gen:
    cg_collector = GraphCollector(neo4j_pass)
    # cg_collector.graphdb.run('MATCH p=()-->() delete p')
    # cg_collector.graphdb.run('match (n) detach delete n')
    cg_collector.graphdb.delete_all()
else:
    cg_collector = None


def exit_handler(signum, frame):
    '''
    捕获ctrl c
    '''
    if graph_gen:
        print('[message] Call Graph generating...')
        cg_collector.save2neo4j()
        print('[message] Call Graph generation finished!')
    if patch_generate:
        with open(patch_collect_file, 'w') as fw:
            fw.write(json.dumps(list(patch_collect)))
        with open(unable2patch_file, 'w') as fw:
            fw.write(json.dumps(list(unable2patch_entry)))
    exit()


signal.signal(signal.SIGINT, exit_handler)
signal.signal(signal.SIGTERM, exit_handler)


class ASTExecutor:

    cur_key = ''  # 当前key值
    namespace = ''  # 当前命名空间
    local_var = None  # 局部变量
    use_list = None  # use语句引入的类、函数

    def __init__(self, cur_key, namespace, local_var, use_list):
        '''
        ast模拟执行
        每当跳转至另一个函数/方法，就重新实例化一个执行器，以控制use列表、namespace、local_var
        （一个函数仅对应一个use列表、namespace、local_var）的作用域
        此外，一个cur_key对应多个函数的执行，因为cur_key用来记录一条执行路径的信息，一条路径可以有多次函数跳转
        cur_key仅在出现多个pop链结、并行执行时才新建
        所以cur_key也可以用对象属性来记录
        use_list要明确到方法
        '''
        self.cur_key = cur_key
        self.namespace = namespace
        self.local_var = local_var
        self.use_list = use_list

    def get_varref(self, node, is_assign=False):
        '''
        递归地获取要赋值的变量的ref，主要用于赋值时的左值
        '''

        # 局部变量
        if type(node) == phpast.Variable and type(node.name) == str:
            return VarRef(self.local_var, node.name[1:])

        # 对象属性
        elif type(node) == phpast.ObjectProperty:

            # 最后一层
            if type(node.node) == phpast.Variable:

                var = node.node.name[1:]  # 变量名
                inst = self.local_var[var]  # 获取对象
                attr = self.execute_ast(node.name)  # 获取属性名

                if type(inst) == ControllableInstance:  # 可控对象，自动赋值
                    if attr not in inst.attr:
                        inst.attr[attr] = ControllableInstance()
                        # 记录root index
                        tmp_index = copy.copy(inst.index)
                        tmp_index.append('attr:'+attr)
                        inst.attr[attr].index = tmp_index

                if inst == None:
                    return None
                if attr not in inst.attr:
                    return None
                return VarRef(inst.attr, attr)

            # 递归解析
            else:
                base = self.execute_ast(node.node)  # 先递归获取base
                name = self.execute_ast(node.name)
                ref = VarRef(base.attr, name)  # base.attrname的ref
                return ref

        # 数组索引
        elif type(node) == phpast.ArrayOffset:
            offset = self.execute_ast(node.expr)
            arr = self.get_varref(node.node)  # 获取arr
            if type(arr) != VarRef or arr.ref == None or type(arr.ref) == str:
                return 'NOTFOUND'

            if arr.key not in arr.ref:
                return 'NOTFOUND'

            # 自动补全
            # 可控对象
            if type(arr.ref[arr.key]) == ControllableInstance and arr.ref[arr.key].classname == None:
                if is_assign:
                    # ArrayAccess
                    tnode = ArrayAccessNode(node.node)
                    self.call_implement_methods(
                        arr.ref[arr.key], '!arrayaccess-set', [], tnode)
                arr.ref[arr.key] = self.controllable_arr_assign(
                    arr.ref[arr.key], offset)
            # 可控数组
            elif type(arr.ref[arr.key]) == PHPArray and arr.ref[arr.key].isControllable and not arr.ref[arr.key].isSanitized:
                if is_assign:
                    # ArrayAccess
                    tnode = ArrayAccessNode(node.node)
                    self.call_implement_methods(
                        arr.ref[arr.key], '!arrayaccess-set', [], tnode)
            # 一般对象
            elif type(arr.ref[arr.key]) == PHPInstance:
                arr.setValue(PHPArray())

            return VarRef(arr.ref[arr.key], offset)

    def check_func_sink(self, funcname, par_li, node):
        '''
        检测调用的函数是否存在污点
        '''

        # PFortifier特殊函数，用来debug；用法：`pfortifier();`
        if funcname == 'pfortifier':
            print('[+] Break point at',
                  f'''"{node.sourcefile}", line {node.lineno}''')

        if funcname == 'phpinfo':
            self.pop_log_report('PHPINFO调用(PHPINFO called)', node)

        if len(par_li) == 0:
            return

        if type(funcname) == ControllableInstance:
            funcname = self.tostr(funcname, node)

        if type(funcname) != str:
            return

        # 任意文件读取
        if funcname in file_read_func:
            if type(par_li[0]) == ControllableInstance:
                par_li[0] = self.tostr(par_li[0], node.params[0].node)
            if type(par_li[0]) != str:
                return
            if 'SOURCE_TOKEN' in par_li[0]:
                self.pop_log_report('任意文件读取(Arbitrary file reading)', node)

        # 任意文件读取2
        if funcname == 'fread':
            if type(par_li[0]) == ControllableInstance:
                self.pop_log_report('任意文件读取(Arbitrary file reading)', node)

        # 任意文件删除
        elif funcname in file_del_func:
            if type(par_li[0]) == ControllableInstance:
                par_li[0] = self.tostr(par_li[0], node.params[0].node)
            if type(par_li[0]) != str:
                return
            if 'SOURCE_TOKEN' in par_li[0]:
                self.pop_log_report('任意文件删除(Arbitrary file deletion)', node)

        # 文件敏感操作1
        elif funcname in file_sensitive_func1:
            if type(par_li[0]) == ControllableInstance:
                par_li[0] = self.tostr(par_li[0], node.params[0].node)
            if type(par_li[0]) != str:
                return
            if 'SOURCE_TOKEN' in par_li[0]:
                self.pop_log_report('文件敏感操作(File sensitive operation)', node)

        # 文件敏感操作2
        elif funcname in file_sensitive_func2:
            for i in range(2):
                if type(par_li[i]) == ControllableInstance:
                    par_li[i] = self.tostr(par_li[i], node.params[i].node)
                if type(par_li[i]) != str:
                    return
            if 'SOURCE_TOKEN' in par_li[0] and 'SOURCE_TOKEN' in par_li[1]:
                self.pop_log_report('文件敏感操作(File sensitive operation)', node)

        # 代码执行
        elif funcname in code_rce:
            if type(par_li[0]) == ControllableInstance:
                par_li[0] = self.tostr(par_li[0], node.params[0].node)
            if type(par_li[0]) != str:
                return
            if 'SOURCE_TOKEN' in par_li[0]:
                self.pop_log_report(
                    '任意代码执行(Arbitrary code execution)', node)

        # preg_replace代码执行
        elif funcname == 'preg_replace':
            for i in range(2):
                if type(par_li[i]) == ControllableInstance:
                    par_li[i] = self.tostr(par_li[i], node.params[i].node)
                if type(par_li[i]) != str:
                    return
            if 'SOURCE_TOKEN' in par_li[0] and 'SOURCE_TOKEN' in par_li[1]:
                self.pop_log_report(
                    'Preg_replace任意代码执行(Preg_replace arbitrary code execution)', node)

        # preg_replace_callback代码执行
        elif funcname == 'preg_replace_callback':
            for i in range(1, 3):
                if type(par_li[i]) == ControllableInstance:
                    par_li[i] = self.tostr(par_li[i], node.params[i].node)
                if type(par_li[i]) != str:
                    return
            if 'SOURCE_TOKEN' in par_li[1] and 'SOURCE_TOKEN' in par_li[2]:
                self.pop_log_report(
                    'Preg_replace_callback任意代码执行(Preg_replace_callback arbitrary code execution)', node)

        # 系统命令注入
        elif funcname in sys_rce:
            if type(par_li[0]) == ControllableInstance:
                par_li[0] = self.tostr(par_li[0], node.params[0].node)
            if type(par_li[0]) != str:
                return
            if 'SOURCE_TOKEN' in par_li[0]:
                self.pop_log_report('系统命令注入(Command injection)', node)

        # mail参数注入
        elif funcname == 'mail':
            if len(par_li) > 4:
                if type(par_li[4]) == ControllableInstance:
                    par_li[4] = self.tostr(par_li[4], node.params[4].node)
                if 'SOURCE_TOKEN' in par_li[4]:
                    self.pop_log_report(
                        'mail()选项注入(mail() options injection)', node)

        # 任意文件写入
        elif funcname == 'file_put_contents':
            for i in range(2):
                if type(par_li[i]) == ControllableInstance:
                    par_li[i] = self.tostr(par_li[i], node.params[i].node)
                if type(par_li[i]) != str:
                    return

            if type(par_li[1]) == str and 'SOURCE_TOKEN' in par_li[1]:
                if 'SOURCE_TOKEN' in par_li[0] or par_li[0][-4:] == '.php':
                    self.pop_log_report(
                        '任意文件写入(Arbitrary file write)', node)

        elif funcname == 'simplexml_load_string':  # XXE1
            if type(par_li[0]) == ControllableInstance:
                par_li[0] = self.tostr(par_li[0], node.params[0].node)
            if type(par_li[0]) != str:
                return
            if 'SOURCE_TOKEN' in par_li[0]:
                self.pop_log_report('XXE', node)

        elif funcname == 'simplexml_load_file':  # XXE2
            if type(par_li[0]) == ControllableInstance:
                par_li[0] = self.tostr(par_li[0], node.params[0].node)
            if type(par_li[0]) != str:
                return
            if 'SOURCE_TOKEN' in par_li[0]:
                self.pop_log_report('XXE', node)

        # ssrf 1
        elif funcname in ssrf_func:
            if type(par_li[0]) == ControllableInstance:
                par_li[0] = self.tostr(par_li[0], node.params[0].node)
            if type(par_li[0]) != str:
                return
            if 'SOURCE_TOKEN' in par_li[0]:
                self.pop_log_report('SSRF', node)

        # SQL注入
        elif funcname in sqli_func2:
            if type(par_li[0]) == ControllableInstance:
                par_li[0] = self.tostr(par_li[0], node.params[0].node)
            if type(par_li[0]) != str:
                return
            if 'SOURCE_TOKEN' in par_li[0]:
                self.pop_log_report('SQL注入(SQL injection)', node)

        # XSS
        elif funcname in xss_func:
            if type(par_li[0]) == ControllableInstance:
                par_li[0] = self.tostr(par_li[0], node.params[0].node)
            if type(par_li[0]) != str:
                return
            if 'SOURCE_TOKEN' in par_li[0]:
                # 去掉print_r(xxx, True) 的情况
                if len(par_li) == 1 or not par_li[1]:
                    self.pop_log_report('XSS', node)

        # 文件上传
        # 第二个参数（目标文件名）可控或者结尾是php，则能够上传php文件
        elif funcname == 'move_uploaded_file':
            if type(par_li[1]) == ControllableInstance:
                par_li[1] = self.tostr(par_li[1], node.params[1].node)
            if type(par_li[1]) != str:
                return
            if 'SOURCE_TOKEN' in par_li[1] or par_li[1][-4:] == '.php':
                self.pop_log_report('文件上传(File uploading)', node)

        # 代码执行2
        elif 'SOURCE_TOKEN' in funcname:
            self.pop_log_report('任意函数调用(Arbitrary function called)', node)

        # SQL注入
        elif funcname in sqli_func:
            if type(par_li[1]) == ControllableInstance:
                par_li[1] = self.tostr(par_li[1], node.params[1].node)
            if type(par_li[1]) != str:
                return
            if 'SOURCE_TOKEN' in par_li[1]:
                self.pop_log_report('SQL注入(SQL injection)', node)

        # 任意文件写入2
        elif funcname == 'fputs' or funcname == 'fwrite':

            if type(par_li[0]) == ControllableInstance:
                if type(par_li[1]) == ControllableInstance:
                    par_li[1] = self.tostr(par_li[1], node.params[1].node)
                if type(par_li[1]) != str:
                    return
                if 'SOURCE_TOKEN' in par_li[1]:
                    self.pop_log_report('任意文件写入(Arbitrary file write)', node)

            elif type(par_li[0]) == PHPInstance:
                t_filename = par_li[0].attr['filename']
                # 文件名可控
                if 'SOURCE_TOKEN' in t_filename or t_filename[-4:] == '.php':
                    # 文件内容可控
                    if 'SOURCE_TOKEN' in par_li[1]:
                        self.pop_log_report(
                            '任意文件写入(Arbitrary file write)', node)

        # ssrf 2
        elif funcname == 'curl_exec':

            if type(par_li[0]) == ControllableInstance:
                self.pop_log_report('SSRF', node)

            elif type(par_li[0]) == PHPInstance:
                tmp_attr = par_li[0].attr
                if 'SOURCE_TOKEN' in tmp_attr['url']:
                    self.pop_log_report('SSRF', node)

    def call_func(self, funcname, par_li, node):
        '''
        创建新的AST执行器以调用函数

        传入：
        funcname：函数名
        par_li：参数列表

        返回值：函数的返回值（没有包装ReturnValue）
        '''
        ret_val = None
        called_func = None

        if type(funcname) == ControllableInstance:
            self.tostr(funcname, node)

        if type(funcname) != str:
            return 'DONTCARE'

        # 没有命名空间，调用函数
        if '\\' not in funcname:

            # 如果是内置函数，直接返回
            if funcname in builtin_func:
                try:
                    ret_val = builtin_func[funcname](self, par_li, node)
                except Exception as e:
                    with open(log_file, 'a') as fw:
                        print('[- error] Builtin func error:', e, funcname, par_li,
                              f'''"{node.sourcefile}", line {node.lineno}''', file=fw)

                self.check_func_sink(funcname, par_li, node)
                return ret_val

            else:  # 不是内置函数，尝试找到要调用的函数实现
                # 如果是自定义函数，两种名称空间拼接情况
                if '\\' + funcname in global_func_dict:
                    called_func = global_func_dict['\\' + funcname]
                elif self.namespace+'\\' + funcname in global_func_dict:
                    called_func = global_func_dict[self.namespace +
                                                   '\\' + funcname]

                self.check_func_sink(funcname, par_li, node)

        else:  # 有命名空间，尝试找到要调用的函数实现
            if funcname in global_func_dict:
                called_func = global_func_dict[funcname]

        if called_func != None:  # 成功找到函数

            # 防止无限递归
            if called_func.name in pop_dict[self.cur_key].normalInfo:
                return None

            # 记录跳转的函数
            pop_dict[self.cur_key].normalInfo.append(called_func.name)
            # 记录调用栈
            pop_dict[self.cur_key].callsiteInfo.append(
                [node.sourcefile, node.lineno])
            pop_dict[self.cur_key].callsiteInfo.append(
                [called_func.sourcefile, called_func.lineno])
            # 记录条件栈长度
            cond_stack_depth.append(len(condition_stack))

            try:  # 捕捉异常，防止栈信息因中断导致不弹出
                # 传递参数
                new_local_var = {}

                for i in range(len(called_func.params)):
                    t_formalpar = called_func.params[i]
                    if i < len(par_li):
                        new_local_var[t_formalpar.name[1:]] = par_li[i]
                    else:  # 超长时，传入默认值
                        new_local_var[t_formalpar.name[1:]
                                      ] = self.execute_ast(t_formalpar.default)

                # 新建AST执行器，执行函数，传出返回值
                # 由于直接使用了当前key，执行完后不用更新当前local_var
                new_executor = ASTExecutor(
                    self.cur_key, called_func.namespace, LocalVarDict(new_local_var), called_func.use_list)

                ret_val = new_executor.execute_ast(called_func)

                if type(ret_val) == ReturnValue:  # 函数调用完毕返回值转化为其真正的值
                    ret_val = ret_val.val
            except Exception:
                pass
            # 执行结束，调用方法出栈
            pop_dict[self.cur_key].normalInfo.pop()
            pop_dict[self.cur_key].callsiteInfo.pop()
            pop_dict[self.cur_key].callsiteInfo.pop()
            cond_stack_depth.pop()
            return ret_val
        else:  # 未找到函数
            return 'DONTCARE'

    def call_closure(self, closure, par_li, node):
        '''
        执行匿名函数
        '''

        # 记录跳转的函数
        pop_dict[self.cur_key].normalInfo.append('closure')

        try:  # 捕捉异常，防止栈信息因中断导致不弹出

            # 传递参数
            new_local_var = {}

            for i in range(len(closure.params)):
                t_formalpar = closure.params[i]
                if i < len(par_li):
                    new_local_var[t_formalpar.name[1:]] = par_li[i]
                else:  # 超长时，传入默认值
                    new_local_var[t_formalpar.name[1:]
                                  ] = self.execute_ast(t_formalpar.default)

            # 新建AST执行器，执行函数，传出返回值
            # 由于直接使用了当前key，执行完后不用更新当前local_var
            new_executor = ASTExecutor(
                self.cur_key, self.namespace, LocalVarDict(new_local_var), {})

            ret_val = new_executor.execute_ast(closure.nodes)

            if type(ret_val) == ReturnValue:  # 函数调用完毕返回值转化为其真正的值
                ret_val = ret_val.val

        except Exception:
            pass

        pop_dict[self.cur_key].normalInfo.pop()  # 执行完毕，出栈

        return ret_val

    def check_method_sink(self, receiver, methodname, par_li, node):
        '''
        检测调用的方法是否存在污点
        '''
        if methodname == None:
            return

        # 使用对象接口的sql注入
        if methodname == 'query':
            if type(receiver) == PHPInstance:  # 如果是对象
                if receiver.classname == 'mysqli' and 'SOURCE_TOKEN' in par_li[0]:
                    self.pop_log_report('SQL注入(SQL injection)', node)

        # 调用的方法名可控
        elif type(methodname) == ControllableInstance or 'SOURCE_TOKEN' in methodname:
            self.pop_log_report('任意方法调用(Arbitrary method called)', node)

    def call_method(self, receiver, methodname, par_li, node, new_key=None):
        '''
        创建新的AST执行器以调用方法
        传入：
        receiver：PHPInstance
        methodname：方法名
        par_li：参数列表
        new_key：新key，只有在多个链结时才有用

        副作用的作用对象：new_key对应的root

        返回值：方法的返回值（没有包装ReturnValue）
        '''

        is_parent = False
        if receiver == 'parent':
            is_parent = True
            receiver = self.local_var['this']

        # 检测是否存在污点
        self.check_method_sink(receiver, methodname, par_li, node)

        if receiver == None or type(receiver) == str:
            return None

        if type(methodname) != str:
            return None

        # 默认使用cur_key
        if new_key == None:
            is_possible_call = False
            new_key = self.cur_key
        else:
            is_possible_call = True

        # 检验当前receiver是否在新key的root中；
        # 可能会因为root中循环引用等情况导致获取到的receiver与root不吻合

        if type(receiver) == ControllableInstance and not self.check_ctrl_in_root(receiver, pop_dict[new_key].root):
            return 'DONTCARE'
        if is_parent:
            if self.local_var['this'].classname not in ext_dict:
                return 'DONTCARE'
            vparent = ext_dict[self.local_var['this'].classname]
            if vparent not in class_dict or methodname not in class_dict[vparent]:
                return 'NOTFOUND'
            # 防止无限递归
            if vparent+'#'+methodname in pop_dict[new_key].normalInfo:
                return 'DONTCARE'
            # 获取方法
            method = class_dict[ext_dict[self.local_var['this'].classname]][methodname]
        else:
            # 防止无限递归
            if receiver.classname+'#'+methodname in pop_dict[new_key].normalInfo:
                return 'DONTCARE'
            # 不存在该方法
            if receiver.classname not in class_dict or methodname not in class_dict[receiver.classname]:
                return 'NOTFOUND'
            # 获取方法
            method = class_dict[receiver.classname][methodname]

        # 找到的不是方法
        if type(method) != phpast.Method:
            return 'DONTCARE'

        # 传递参数
        new_local_var = {}
        new_local_var['this'] = receiver  # 传入this

        for i in range(len(method.params)):
            t_formalpar = method.params[i]
            if i < len(par_li):
                new_local_var[t_formalpar.name[1:]] = par_li[i]
            else:  # 超长时，传入默认值
                new_local_var[t_formalpar.name[1:]
                              ] = self.execute_ast(t_formalpar.default)

        # 尝试获取use语句列表
        if hasattr(method, 'use_list'):
            use_list = method.use_list
        else:
            use_list = {}

        # 经过call_possible_methods
        if is_possible_call:
            # 同步局部变量
            self.update_local_vars(new_key, new_local_var)
            # pm调用时多加一层条件栈用来隔离
            condition_stack.append(set())

        # 记录跳转的方法
        if is_parent:
            pop_dict[new_key].normalInfo.append(vparent+'#'+methodname)
        else:
            pop_dict[new_key].normalInfo.append(
                receiver.classname+'#'+methodname)

        # print(pop_dict[new_key].normalInfo[-2:],
        #       len(pop_dict[new_key].normalInfo), len(pop_dict[new_key].callsiteInfo))

        # __call的情况包裹一层CallNode，以在patch生成阶段识别出__call跳转
        if is_possible_call:
            if methodname == '__call':
                jmp_node[new_key][-1] = CallNode(jmp_node[new_key][-1])

        # 记录调用栈
        pop_dict[new_key].callsiteInfo.append(
            [node.sourcefile, node.lineno])
        pop_dict[new_key].callsiteInfo.append(
            [method.sourcefile, method.lineno])
        # 记录条件栈长度
        cond_stack_depth.append(len(condition_stack))

        ret_val = None

        try:  # 捕捉异常，防止栈信息因中断导致不弹出

            if hasattr(method, 'namespace'):
                ns = method.namespace
            else:
                ns = ''

            # 新建AST执行器，执行函数，传出返回值
            new_executor = ASTExecutor(
                new_key, ns, LocalVarDict(new_local_var), use_list)

            ret_val = new_executor.execute_ast(method)

            # 由于新建了执行器，返回时需要同步到当前local_var
            # 对于possible_call的情况，由于需要meet操作，在这里不同步，meet时再同步
            if not is_possible_call:
                self.update_local_vars(new_key, self.local_var)

            if type(ret_val) == ReturnValue:  # 函数调用完毕返回值转化为其真正的值
                ret_val = ret_val.val

        except Exception as e:
            # raise e
            # print(e)
            pass

        if is_possible_call:
            condition_stack.pop()  # 条件栈出栈

        # 执行结束，调用方法出栈
        pop_dict[new_key].normalInfo.pop()
        # callsiteInfo是成对的
        pop_dict[new_key].callsiteInfo.pop()
        pop_dict[new_key].callsiteInfo.pop()
        cond_stack_depth.pop()

        return ret_val

    def call_static_method(self, classname, methodname, par_li, node, new_key=None):
        '''
        创建新的AST执行器以调用静态方法
        传入：
        classname：类名
        methodname：方法名
        par_li：参数列表
        new_key：新key，只有在多个链结时才有用

        返回值：方法的返回值（没有包装ReturnValue）
        '''

        ret_val = None
        # 不存在该方法
        if classname not in class_dict or methodname not in class_dict[classname]:
            return 'NOTFOUND'

        method = class_dict[classname][methodname]  # 获取方法

        # 传递参数
        new_local_var = {
            'this': PHPInstance(classname)
        }  # this用对象来代替（本来应该是类名）

        for i in range(len(method.params)):
            t_formalpar = method.params[i]
            if i < len(par_li):
                new_local_var[t_formalpar.name[1:]] = par_li[i]
            else:  # 超长时，传入默认值
                new_local_var[t_formalpar.name[1:]
                              ] = self.execute_ast(t_formalpar.default)

        # 防止无限递归
        if classname+'#'+methodname in pop_dict[self.cur_key].normalInfo:
            return 'DONTCARE'

        # 尝试获取use语句列表
        if hasattr(method, 'use_list'):
            use_list = method.use_list
        else:
            use_list = {}

        if new_key == None:
            new_key = self.cur_key  # 默认使用cur_key

        # 记录跳转的方法
        pop_dict[new_key].normalInfo.append(classname+'#'+methodname)

        # 记录调用栈
        pop_dict[new_key].callsiteInfo.append([node.sourcefile, node.lineno])
        pop_dict[new_key].callsiteInfo.append(
            [method.sourcefile, method.lineno])
        # 记录条件栈长度
        cond_stack_depth.append(len(condition_stack))

        try:  # 捕捉异常，防止栈信息因中断导致不弹出
            if hasattr(method, 'namespace'):
                ns = method.namespace
            else:
                ns = '\\'

            # 新建AST执行器，执行函数，传出返回值
            new_executor = ASTExecutor(
                new_key, ns, LocalVarDict(new_local_var), use_list)

            ret_val = new_executor.execute_ast(method)

            # 由于新建了执行器，返回时需要同步到当前local_var
            for varname in self.local_var:
                if type(self.local_var[varname]) == ControllableInstance:
                    self.local_var[varname] = self.get_inner_inst(self.local_var[varname].index,
                                                                  target_inst=pop_dict[new_key].root)

            if type(ret_val) == ReturnValue:  # 函数调用完毕返回值转化为其真正的值
                ret_val = ret_val.val

        except Exception:
            pass

        # 执行结束，调用方法出栈
        pop_dict[new_key].normalInfo.pop()
        # callsiteInfo是成对的
        pop_dict[new_key].callsiteInfo.pop()
        pop_dict[new_key].callsiteInfo.pop()
        cond_stack_depth.pop()
        return ret_val

    def get_priority(self, obj):
        '''
        获取对象的保留优先级
        '''
        priority = 0
        # 可控对象
        if type(obj) == ControllableInstance:
            if obj.classname == None:
                priority = 4
            else:
                priority = 2
        # 可控数组
        elif type(obj) == PHPArray and obj.isControllable:
            priority = 3
        # source字符串
        elif type(obj) == str and source_token in obj:
            priority = 1
        return priority

    def call_possible_methods(self, receiver, methodname,  par_li, node):
        '''
        根据方法名和参数个数，调用可能的方法
        存在并行执行（但在方法执行内部已经申请了新AST执行器了，这里不需要再申请）
        会在原receiver的复制体上进行
        此外，如果外层需要返回值，则在本方法中就要把返回值对应的receiver和key都赋值成对应的值
        '''
        ret_val = None

        if self.check_in_cond(receiver.index):
            return

        if type(methodname) == ControllableInstance:
            self.pop_log_report('任意方法调用(Arbitrary method called)', node)

        if type(methodname) != str:
            return ret_val

        brief_par = ''  # 参数信息摘要

        for i in range(len(par_li)):
            if type(par_li[i]) == ControllableInstance:
                brief_par += 'c'  # 可控
            else:
                brief_par += 'n'

        pm = methodname+':'+brief_par

        # 防止POP路径爆炸
        if pm in pop_dict[self.cur_key].possibleInfo:
            return ret_val

        if self.cur_key not in jmp_node:
            jmp_node[self.cur_key] = []

        # 记录firstJmpIndex
        firstJmpRM = False
        if not pop_dict[self.cur_key].firstJmpIndex:
            pop_dict[self.cur_key].firstJmpIndex = receiver.index
            firstJmpRM = True

        # jmp_node在pm_offset记录前入栈
        jmp_node[self.cur_key].append(node)

        # 在append之前记录pm_offset，因为当前还没有调用PM
        pm_offset[pm] = [
            len(pop_dict[self.cur_key].normalInfo),
            len(pop_dict[self.cur_key].possibleInfo),
            len(pop_dict[self.cur_key].callsiteInfo),
            len(jmp_node[self.cur_key]),
        ]

        # 在summary中查找sink
        if pm in pm_summary:
            # 当前PM深度大于等于summary深度才使用summary
            if len(pop_dict[self.cur_key].possibleInfo) >= pm_summary[pm].pm_depth:
                # 直接查询对应的sink，并记录其结果
                pms = pm_summary[pm]
                pm_summary[pm].ret_val = pms.ret_val
                self.pop_log_report_summary(pms, node)
                receiver.classname = pms.assign_receiver
                del pm_offset[pm]
                jmp_node[self.cur_key].pop()
                if firstJmpRM:
                    pop_dict[self.cur_key].firstJmpIndex = None
                return pms.ret_val

        # 初始化
        if use_pm_summary:
            pm_summary[pm] = PMSummary(
                len(pop_dict[self.cur_key].possibleInfo))

        # 信息入栈，放在summary使用之后，因为summary不需要记录当前将调用的方法本身（summary中已有了）
        pop_dict[self.cur_key].possibleInfo.append(pm)

        # 一般方法调用，并且存在__call
        if methodname[:2] != '__' and '__call' in attr_func_dict:
            next_classes_call = attr_func_dict['__call']
        else:
            next_classes_call = []

        # 选择函数名和必填参数个数同时匹配的方法（参数个数>=必填参数个数）
        next_classes_normal = []
        if methodname in attr_func_dict:
            for tmp_class in attr_func_dict[methodname]:

                # 只有属性不存在时才触发（或者不可访问）
                if methodname in ('__get', '__set', '__isset', '__unset'):
                    if par_li[0] in class_dict[tmp_class]:
                        continue

                tmp_method = class_dict[tmp_class][methodname]
                tmp_callpar_num = len(par_li)
                tmp_methodpar_num = 0
                for para in tmp_method.params:
                    if para.default != None:
                        break
                    tmp_methodpar_num += 1

                # 参数个数>=必填参数个数
                if tmp_callpar_num >= tmp_methodpar_num:
                    next_classes_normal.append(tmp_class)

        # 只有不存在该方法时才调用__call
        next_classes = copy.copy(next_classes_normal)
        for tmp in next_classes_call:
            if tmp not in next_classes_normal:
                next_classes.insert(0, tmp)

        # target上下文
        if len(next_classes) > 0:
            pop_dict['target'] = copy.deepcopy(
                pop_dict[self.cur_key])  # 复制POP链信息
            pop_dict['target'].root.key = 'target'

        # 调用每个可能的方法，贪心法获取可控的返回值
        # 执行在复制体上进行，meet之后的返回值对应的root储存到当前root
        ret_prior = 0  # 初始化返回值优先级
        for i in range(len(next_classes)):
            if methodname in class_dict[next_classes[i]]:
                realname = methodname
                tmp_par_li = par_li
            else:
                realname = '__call'  # __call参数构造
                tmp_par_li = [methodname, par_li]
            try:
                if 'private' in class_dict[next_classes[i]][realname].modifiers:
                    if self.local_var['this'].classname != next_classes[i]:
                        continue
            except Exception:
                pass

            # 新建key的主要目的：在向内执行方法的时候，会对可控对象进行修改，
            # 在这里为了保留可控变量，需要新建key；对于其他调用魔术方法的情况同样需要
            # 处理时假设向内执行都没有副作用
            new_key = random_string()  # 生成新key
            pop_dict[new_key] = copy.deepcopy(
                pop_dict[self.cur_key])  # 复制POP链信息
            pop_dict[new_key].root.key = new_key

            jmp_node[new_key] = copy.copy(jmp_node[self.cur_key])

            # 获取复制后的receiver
            t_receiver = self.get_inner_inst(receiver.index,
                                             target_inst=pop_dict[new_key].root)

            # 由于分支执行等情况导致index对应的对象不匹配的情况，需要进行修正
            if type(t_receiver) != type(receiver):
                t_ref = self.get_inner_inst(
                    receiver.index, True, pop_dict[new_key].root)
                t_ref.ref[t_ref.key] = copy.deepcopy(receiver)
                t_receiver = t_ref.ref[t_ref.key]

            if type(t_receiver) != ControllableInstance:
                continue

            # 对receiver的类名进行赋值
            t_receiver.classname = next_classes[i]
            try:  # 捕捉异常，防止栈信息因中断导致不弹出
                tmp_ret = self.call_method(
                    t_receiver, realname, tmp_par_li, node, new_key)
            except Exception:
                pass

            # 贪心法meet
            tmp_prior = self.get_priority(tmp_ret)  # 获取临时返回值的保留优先级
            if tmp_prior > ret_prior:  # 优先级高时，meet到target
                ret_val = tmp_ret
                pop_dict['target'] = pop_dict[new_key]
                ret_prior = tmp_prior
            else:  # 否则不meet
                pass

            # 执行结束，删除新key
            del pop_dict[new_key]
            del jmp_node[new_key]

        if len(next_classes) > 0:
            # target同步到cur_key
            pop_dict[self.cur_key] = pop_dict['target']
            # 同步局部变量
            self.update_local_vars('target', self.local_var)

        if firstJmpRM:
            pop_dict[self.cur_key].firstJmpIndex = None

        # jmp_node出栈
        jmp_node[self.cur_key].pop()

        # 信息出栈
        pop_dict[self.cur_key].possibleInfo.pop()
        # 删除记录
        del pm_offset[pm]

        # 贪心法，由于调用了可能的方法后，对应的对象被赋值，导致后续无法继续查找
        # 这里采用了宽松的策略，将其还原为未赋值的状态
        cur_receiver = self.get_inner_inst(
            receiver.index, target_inst=pop_dict[self.cur_key].root)
        cur_receiver.classname = None

        # 记录ret_val，这里本来需要记录receiver的类名的，由于宽松的策略，不再记录
        if use_pm_summary:
            pm_summary[pm].ret_val = ret_val

        if gc_switch:
            gc.collect()

        return ret_val

    def call_implement_methods(self, receiver, impl, par_li, node):
        '''
        根据接口类型，调用可能的方法
        存在并行执行（但在方法执行内部已经申请了新AST执行器了，这里不需要再申请）
        会在原receiver的复制体上进行
        此外，如果外层需要返回值，则在本方法中就要把返回值对应的receiver和key都赋值成对应的值
        '''
        ret_val = None

        if self.check_in_cond(receiver.index):
            return

        brief_par = ''  # 参数信息摘要

        for i in range(len(par_li)):
            if type(par_li[i]) == ControllableInstance:
                brief_par += 'c'  # 可控
            else:
                brief_par += 'n'

        pm = impl+':'+brief_par

        # 防止POP路径爆炸
        if pm in pop_dict[self.cur_key].possibleInfo:
            return ret_val

        mtd = None
        if '-' in impl:
            impl, mtd = impl.split('-')

        if self.cur_key not in jmp_node:
            jmp_node[self.cur_key] = []

        # 记录firstJmpIndex
        firstJmpRM = False
        if not pop_dict[self.cur_key].firstJmpIndex:
            pop_dict[self.cur_key].firstJmpIndex = receiver.index
            firstJmpRM = True

        # jmp_node在pm_offset记录前入栈
        jmp_node[self.cur_key].append(node)

        # 在append之前记录pm_offset，因为当前还没有调用PM
        pm_offset[pm] = [
            len(pop_dict[self.cur_key].normalInfo),
            len(pop_dict[self.cur_key].possibleInfo),
            len(pop_dict[self.cur_key].callsiteInfo),
            len(jmp_node[self.cur_key]),
        ]

        # 在summary中查找sink
        if pm in pm_summary:
            # 当前PM深度大于等于summary深度才使用summary
            if len(pop_dict[self.cur_key].possibleInfo) >= pm_summary[pm].pm_depth:
                # 直接查询对应的sink，并记录其结果
                pms = pm_summary[pm]
                pm_summary[pm].ret_val = pms.ret_val
                self.pop_log_report_summary(pms, node)
                receiver.classname = pms.assign_receiver
                del pm_offset[pm]
                jmp_node[self.cur_key].pop()
                if firstJmpRM:
                    pop_dict[self.cur_key].firstJmpIndex = None
                return pms.ret_val

        # 初始化
        if use_pm_summary:
            pm_summary[pm] = PMSummary(
                len(pop_dict[self.cur_key].possibleInfo))

        # 信息入栈，放在summary使用之后，因为summary不需要记录当前将调用的方法本身（summary中已有了）
        pop_dict[self.cur_key].possibleInfo.append(pm)

        # 选择函数名和必填参数个数同时匹配的方法（参数个数>=必填参数个数）
        next_classes = []

        if impl in attr_func_dict:
            next_classes = attr_func_dict[impl]

        # target上下文
        if len(next_classes) > 0:
            pop_dict['target'] = copy.deepcopy(
                pop_dict[self.cur_key])  # 复制POP链信息
            pop_dict['target'].root.key = 'target'

        # 调用每个可能的方法，贪心法获取可控的返回值
        # 执行在复制体上进行，meet之后的返回值对应的root储存到当前root
        for i in range(len(next_classes)):
            # 新建key的主要目的：在向内执行方法的时候，会对可控对象进行修改，
            # 在这里为了保留可控变量，需要新建key；对于其他调用魔术方法的情况同样需要
            # 处理时假设向内执行都没有副作用
            new_key = random_string()  # 生成新key
            pop_dict[new_key] = copy.deepcopy(
                pop_dict[self.cur_key])  # 复制POP链信息
            pop_dict[new_key].root.key = new_key

            jmp_node[new_key] = copy.copy(jmp_node[self.cur_key])

            # 获取复制后的receiver
            t_receiver = self.get_inner_inst(receiver.index, True,
                                             target_inst=pop_dict[new_key].root)

            if type(t_receiver) != VarRef:
                continue

            # implememt相关的receiver比较特殊，比如数组，这里用一个“假”receiver来代替
            fake_rec = ControllableInstance()
            fake_rec.index = receiver.index
            t_receiver.setValue(fake_rec)

            t_receiver = t_receiver.ref[t_receiver.key]

            if type(t_receiver) != ControllableInstance:
                continue

            # 对receiver的类名进行赋值
            t_receiver.classname = next_classes[i]

            if impl == '!iterator':
                try:  # 捕捉异常，防止栈信息因中断导致不弹出
                    # rewind (指针移动到第一个元素)
                    self.call_method(t_receiver, 'rewind',
                                     par_li, node, new_key)
                    # valid（验证当前array是否valid，返回True/False）
                    valid_res = self.call_method(t_receiver, 'valid',
                                                 par_li, node, new_key)
                    if valid_res != False:  # valid结果非False时才继续执行
                        self.call_method(t_receiver, 'current',
                                         par_li, node, new_key)
                        self.call_method(t_receiver, 'key',
                                         par_li, node, new_key)
                        self.call_method(t_receiver, 'next',
                                         par_li, node, new_key)
                except Exception:
                    pass
            elif mtd == 'set':  # offsetSet：设置key对应元素
                try:  # 捕捉异常，防止栈信息因中断导致不弹出
                    self.call_method(t_receiver, 'offsetSet',
                                     par_li, node, new_key)
                except Exception:
                    pass
            elif mtd == 'get':  # offsetGet：获取key对应元素
                try:  # 捕捉异常，防止栈信息因中断导致不弹出
                    self.call_method(t_receiver, 'offsetGet',
                                     par_li, node, new_key)
                except Exception:
                    pass

            # 执行结束，删除新key
            del pop_dict[new_key]
            del jmp_node[new_key]

        if len(next_classes) > 0:
            # target同步到cur_key
            pop_dict[self.cur_key] = pop_dict['target']
            # 同步局部变量
            self.update_local_vars('target', self.local_var)

        if firstJmpRM:
            pop_dict[self.cur_key].firstJmpIndex = None

        # jmp_node出栈
        jmp_node[self.cur_key].pop()
        # 信息出栈
        pop_dict[self.cur_key].possibleInfo.pop()

        # 删除记录
        del pm_offset[pm]

        # 贪心法，由于调用了可能的方法后，对应的对象被赋值，导致后续无法继续查找
        # 这里采用了宽松的策略，将其还原为未赋值的状态
        cur_receiver = self.get_inner_inst(
            receiver.index, target_inst=pop_dict[self.cur_key].root)
        cur_receiver.classname = None

        # 记录ret_val，这里本来需要记录receiver的类名的，由于宽松的策略，不再记录
        if use_pm_summary:
            pm_summary[pm].ret_val = ret_val

        if gc_switch:
            gc.collect()

        return ret_val

    def get_inner_inst(self, indexes=None, get_ref=False, target_inst=None):
        '''
        根据index链获取当前root（或特定inst）中对应的子对象或其索引
        '''
        if target_inst != None:
            root = target_inst
        else:
            root = pop_dict[self.cur_key].root

        if len(indexes) == 0:
            return root

        tmp_indexes = copy.copy(indexes)

        if get_ref:  # 如果是获取ref，只索引到倒数第二层
            tmp_indexes = tmp_indexes[:-1]

        # 获取索引对应的对象
        for index in tmp_indexes:
            vtype, ind = index.split(':')

            try:
                if vtype == 'attr':
                    root = root.attr[ind]
                elif vtype == 'key':
                    root = root[ind]
            except Exception:
                return None

        if get_ref:  # 返回ref
            # 获取倒数一级索引
            vtype, ind = indexes[-1].split(':')
            if vtype == 'attr':
                inst = VarRef(root.attr, ind)
            elif vtype == 'key':
                inst = VarRef(root, ind)

        else:  # 返回实例本身
            inst = root

        return inst

    def tostr(self, val, node):
        '''
        结点需要字符串化时调用
        如果结点是可控对象，则可以触发tostring方法
        '''

        if type(val) == str:
            return val

        elif val == None:
            return 'NOTFOUND'

        # 可控对象，可以触发toString
        elif type(val) == ControllableInstance and val.classname == None:
            # 这里存在并行执行：可以调用toString，也可以作为可控字符串
            # 由于call_possible_methods会产生"副作用"，最外层的可控变量引用可能被覆盖，
            # 导致controllable_assign对应该保留值的局部变量赋值失败，这里对当前局部变量进行备份

            root_bak = copy.deepcopy(pop_dict[self.cur_key].root)  # 备份当前root
            local_var_bak = copy.deepcopy(self.local_var)  # 备份当前局部变量
            val_ind = val.index  # 记录val的index

            # 备份的root同步到备份的局部变量
            for varname in local_var_bak:

                if type(local_var_bak[varname]) == ControllableInstance:
                    local_var_bak[varname] = self.get_inner_inst(local_var_bak[varname].index,
                                                                 target_inst=root_bak)
                elif type(local_var_bak[varname]) == PHPArray:
                    for tmpkey in local_var_bak[varname]:
                        if type(local_var_bak[varname][tmpkey]) == ControllableInstance:
                            local_var_bak[varname][tmpkey] = self.get_inner_inst(local_var_bak[varname][tmpkey].index,
                                                                                 target_inst=root_bak)

            node = ToStringNode(node)

            try:  # 这里防止报错后返回source字符串失败，进行异常处理
                self.call_possible_methods(val, '__toString', [], node)

                # 执行结束，还原局部变量、root
                del self.local_var
                del pop_dict[self.cur_key].root
                self.local_var = local_var_bak
                pop_dict[self.cur_key].root = root_bak
                val = self.get_inner_inst(val_ind, target_inst=root_bak)

                # 将可控对象赋值为SOURCE，并返回
                return self.controllable_assign(val, source_token)
            except Exception as e:
                return source_token

        else:
            return 'NOTFOUND'

    def controllable_arr_assign(self, controllable, offset):
        '''
        将可控对象赋值为数组或字典，并返回赋值的数组
        同时更新root和local_var中的指针
        '''

        # 获取该对象的索引，用于覆盖

        inst_ref = self.get_inner_inst(
            controllable.index, get_ref=True)
        if inst_ref == None:
            return
        # root和controllable不匹配
        if inst_ref.key not in inst_ref.ref:
            return 'DONTCARE'

        orig_inst = inst_ref.ref[inst_ref.key]  # 暂存原始对象

        # 可控对象，赋值为字符串
        if type(offset) == ControllableInstance and offset.classname == None:
            offset = self.controllable_assign(offset, source_token)

        if type(offset) == str:
            pass
        elif type(offset) == int:
            offset = str(offset)
        elif offset == None:
            offset = '0'
        # 非正常情况
        else:
            return 'DONTCARE'

        inst_ref.ref[inst_ref.key] = PHPArray()
        inst_ref.ref[inst_ref.key].isControllable = True
        inst_ref.ref[inst_ref.key].index = controllable.index
        inst_ref.ref[inst_ref.key][offset] = ControllableInstance()

        # 记录root index
        tmp_index = copy.copy(controllable.index)
        tmp_index.append(f'key:{offset}')
        inst_ref.ref[inst_ref.key][offset].index = tmp_index

        # 同步局部变量
        for varname in self.local_var:
            if self.local_var[varname] is orig_inst:
                self.local_var[varname] = inst_ref.ref[inst_ref.key]

            elif type(self.local_var[varname]) == PHPArray:
                for tmpkey in self.local_var[varname]:
                    if self.local_var[varname][tmpkey] is orig_inst:
                        self.local_var[varname][tmpkey] = inst_ref.ref[inst_ref.key]

        return inst_ref.ref[inst_ref.key]

    def controllable_assign(self, controllable, val):
        '''
        将可控对象赋值为具体值，并返回该值
        同时更新root和local_var中的指针
        '''

        if not hasattr(controllable, 'index'):
            return val

        # 获取该对象的root索引，用于覆盖
        inst_ref = self.get_inner_inst(
            controllable.index, get_ref=True)

        if inst_ref == None:
            return val

        try:
            orig_inst = inst_ref.ref[inst_ref.key]  # 暂存原始对象
        except Exception:  # root和controllable不匹配
            return val

        # root赋值
        inst_ref.setValue(val)

        # 同步局部变量
        for varname in self.local_var:
            if self.local_var[varname] is orig_inst:
                self.local_var[varname] = val

            elif type(self.local_var[varname]) == PHPArray:
                for tmpkey in self.local_var[varname]:
                    if self.local_var[varname][tmpkey] is orig_inst:
                        self.local_var[varname][tmpkey] = val

        return val

    def update_local_vars(self, from_key, to_local_var):
        '''
        局部变量同步
        新建key时，需要把新局部变量中的可控变量全部改为新建的key中的局部变量
        目前只处理直接的对象和单层字典、数组（不处理嵌套）
        '''

        for varname in to_local_var:
            if type(to_local_var[varname]) == ControllableInstance:
                to_local_var[varname] = self.get_inner_inst(to_local_var[varname].index,
                                                            target_inst=pop_dict[from_key].root)
            elif type(to_local_var[varname]) == PHPArray:
                for tmpkey in to_local_var[varname]:
                    if type(to_local_var[varname][tmpkey]) == ControllableInstance:
                        to_local_var[varname][tmpkey] = self.get_inner_inst(to_local_var[varname][tmpkey].index,
                                                                            target_inst=pop_dict[from_key].root)

    def pop_log_report(self, vul_type, node):
        '''
        报告并记录查找到的可利用链
        '''

        global find_num

        sinkLineno = f'''"{node.sourcefile}", line {node.lineno}'''

        # 记录PM summary
        if use_pm_summary:
            # 跳过第一个链节
            for pm in pop_dict[self.cur_key].possibleInfo[1:]:
                t_offset = pm_offset[pm]
                newSink = SinkInfo()
                newSink.normalInfo = pop_dict[self.cur_key].normalInfo[t_offset[0]:]
                newSink.possibleInfo = pop_dict[self.cur_key].possibleInfo[t_offset[1]:]
                newSink.callsiteInfo = pop_dict[self.cur_key].callsiteInfo[t_offset[2]:]
                newSink.jmpNode = jmp_node[self.cur_key][t_offset[3]:]
                newSink.vulType = vul_type
                newSink.sinkLineNo = sinkLineno
                pm_summary[pm].sinkInfo.append(newSink)

        if self.cur_key not in jmp_node:
            jmp_node[self.cur_key] = []

        # 记录调用图
        if graph_gen:
            # 储存第一个caller
            callerClass, callerMtd = pop_dict[self.cur_key].normalInfo[0].split(
                '#')
            tmp_mtd = class_dict[callerClass][callerMtd]
            cg_collector.saveMethod(callerClass, callerMtd,
                                    tmp_mtd.sourcefile, tmp_mtd.lineno)
            for i in range(1, len(pop_dict[self.cur_key].normalInfo)):
                # 储存callee
                calleeClass, calleeMtd = pop_dict[self.cur_key].normalInfo[i].split(
                    '#')
                tmp_mtd = class_dict[calleeClass][calleeMtd]
                cg_collector.saveMethod(calleeClass, calleeMtd,
                                        tmp_mtd.sourcefile, tmp_mtd.lineno)
                csFile, csLineno = pop_dict[self.cur_key].callsiteInfo[2*i-1]
                cg_collector.saveCallsite(callerClass, callerMtd,
                                          calleeClass, calleeMtd, csFile, csLineno)

                # 当前callee作为下一个caller
                callerClass, callerMtd = calleeClass, calleeMtd

            # 记录graph中的sink
            cg_collector.setSinkMethod(
                pop_dict[self.cur_key].normalInfo[-1], node.lineno)

        # 获取entry
        entry_func = pop_dict[self.cur_key].normalInfo[:entry_depth]
        entry_func = ';'.join(entry_func)

        # 对同一entry进行sink筛选
        if filter_sink:
            if entry_func in filter_sink_dict:
                # if pop_dict[self.cur_key].normalInfo[-1] in filter_sink_dict[entry_func]:
                if sinkLineno in filter_sink_dict[entry_func]:
                    return

        # 避免同一个入口记录过多的sink链
        if skip_overdetected:
            if len(pop_dict[self.cur_key].normalInfo) >= entry_depth:
                if entry_func in entry_found_popnum:
                    if entry_found_popnum[entry_func] >= each_entry_early_stop_num:
                        return

        # 确认要记录该链时

        # 记录sink筛选信息
        if filter_sink:
            if entry_func not in filter_sink_dict:
                filter_sink_dict[entry_func] = set()
            filter_sink_dict[entry_func].add(sinkLineno)
            # filter_sink_dict[entry_func].add(
            #     pop_dict[self.cur_key].normalInfo[-1])

        # 记录entry对应的pop链数量
        if len(pop_dict[self.cur_key].normalInfo) >= entry_depth:
            if entry_func not in entry_found_popnum:
                entry_found_popnum[entry_func] = 0
            entry_found_popnum[entry_func] += 1

        store_key = random_string()
        # patch生成
        if patch_generate:
            with open(patch_file, 'a') as fw:
                patch = autoPatch.get_patch(jmp_node[self.cur_key])
                if patch == None:
                    sugg = self.wakeup_suggest()
                    print(json.dumps(
                        {store_key: sugg}), file=fw)
                    unable2patch_entry.add(json.dumps(
                        pop_dict[self.cur_key].normalInfo[:entry_depth]))
                else:
                    print(json.dumps(
                        {store_key: patch}), file=fw)
                    patch_collect.add(json.dumps(patch))

        # 记录sink信息
        vul_info = {}
        vul_info['key'] = store_key
        vul_info['vulType'] = vul_type
        vul_info['entry'] = ';'.join(
            pop_dict[self.cur_key].normalInfo[:entry_depth])
        vul_info['existWakeup'] = pop_dict[self.cur_key].wakeupExist
        vul_info['sink'] = sinkLineno
        vul_info['possibleJmpStack'] = pop_dict[self.cur_key].possibleInfo
        vul_info['funcStack'] = pop_dict[self.cur_key].normalInfo
        vul_info['callStack'] = pop_dict[self.cur_key].callsiteInfo

        with open(result_file, 'a', encoding='utf8') as fw:
            print(json.dumps(vul_info, ensure_ascii=False), end='', file=fw)
            print(file=fw)

        find_num += 1

        # 记录当前时间
        info_log(time.time())
        print(json.dumps(vul_info, ensure_ascii=False))

    def pop_log_report_summary(self, summ: PMSummary, node):
        '''
        根据summary信息报告漏洞
        '''
        global find_num

        # 记录调用图
        if len(summ.sinkInfo) > 0 and graph_gen:
            # 储存第一个caller
            callerClass, callerMtd = pop_dict[self.cur_key].normalInfo[0].split(
                '#')
            tmp_mtd = class_dict[callerClass][callerMtd]
            cg_collector.saveMethod(callerClass, callerMtd,
                                    tmp_mtd.sourcefile, tmp_mtd.lineno)
            for i in range(1, len(pop_dict[self.cur_key].normalInfo)):
                # 储存callee
                calleeClass, calleeMtd = pop_dict[self.cur_key].normalInfo[i].split(
                    '#')
                tmp_mtd = class_dict[calleeClass][calleeMtd]
                cg_collector.saveMethod(calleeClass, calleeMtd,
                                        tmp_mtd.sourcefile, tmp_mtd.lineno)
                csFile, csLineno = pop_dict[self.cur_key].callsiteInfo[2*i-1]
                cg_collector.saveCallsite(callerClass, callerMtd,
                                          calleeClass, calleeMtd, csFile, csLineno)

                # 当前callee作为下一个caller
                callerClass, callerMtd = calleeClass, calleeMtd

        for sink in summ.sinkInfo:
            # 对调用栈进行筛选，有重复的情况不记录
            if len(set(pop_dict[self.cur_key].normalInfo).intersection(set(sink.normalInfo))) > 0:
                continue
            if len(set(pop_dict[self.cur_key].possibleInfo).intersection(set(sink.possibleInfo))) > 0:
                continue

            normalInfo = pop_dict[self.cur_key].normalInfo + sink.normalInfo
            possibleInfo = pop_dict[self.cur_key].possibleInfo + \
                sink.possibleInfo

            # 修正中间链结
            if self.cur_key not in jmp_node:
                jmp_node[self.cur_key] = []
            tmp_len = len(pop_dict[self.cur_key].callsiteInfo)
            callsiteInfo = pop_dict[self.cur_key].callsiteInfo + \
                sink.callsiteInfo
            callsiteInfo[tmp_len] = [node.sourcefile, node.lineno]
            # 由于call结点的信息在具体的方法确定时才确定，这里对__call进行修正
            if pop_dict[self.cur_key].normalInfo[-1][-7:] == '#__call':
                jmpNode = jmp_node[self.cur_key] + \
                    CallNode(sink.jmpNode[0]) + sink.jmpNode[1:]
            else:
                jmpNode = jmp_node[self.cur_key] + sink.jmpNode

            # PM summary得到的sink也要记录到PM summary，有点递归的意思
            # 跳过第一个链节
            for pm in pop_dict[self.cur_key].possibleInfo[1:]:
                t_offset = pm_offset[pm]
                newSink = SinkInfo()
                newSink.normalInfo = normalInfo[t_offset[0]:]
                newSink.possibleInfo = possibleInfo[t_offset[1]:]
                newSink.callsiteInfo = callsiteInfo[t_offset[2]:]
                newSink.jmpNode = jmpNode[t_offset[3]:]
                newSink.vulType = sink.vulType
                newSink.sinkLineNo = sink.sinkLineNo
                pm_summary[pm].sinkInfo.append(newSink)

            # 获得entry
            entry_func = normalInfo[:entry_depth]
            entry_func = ';'.join(entry_func)

            # 对同一entry进行sink筛选
            if filter_sink:
                if entry_func in filter_sink_dict:
                    # if normalInfo[-1] in filter_sink_dict[entry_func]:
                    if sink.sinkLineNo in filter_sink_dict[entry_func]:
                        return

            # 避免同一个入口记录过多的sink链
            if skip_overdetected:
                if len(normalInfo) >= entry_depth:
                    if entry_func in entry_found_popnum:
                        if entry_found_popnum[entry_func] >= each_entry_early_stop_num:
                            return

            # 确认要记录该链时

            # 记录sink筛选信息
            if filter_sink:
                if entry_func not in filter_sink_dict:
                    filter_sink_dict[entry_func] = set()
                filter_sink_dict[entry_func].add(sink.sinkLineNo)
                # filter_sink_dict[entry_func].add(normalInfo[-1])

            # 记录entry对应的pop链数量
            if len(normalInfo) >= entry_depth:
                if entry_func not in entry_found_popnum:
                    entry_found_popnum[entry_func] = 0
                entry_found_popnum[entry_func] += 1

            store_key = random_string()
            # patch生成
            if patch_generate:
                with open(patch_file, 'a') as fw:
                    patch = autoPatch.get_patch(jmpNode)
                    if patch == None:
                        sugg = self.wakeup_suggest()
                        print(json.dumps(
                            {store_key: sugg}), file=fw)
                        unable2patch_entry.add(
                            json.dumps(normalInfo[:entry_depth]))
                    else:
                        print(json.dumps({store_key: patch}), file=fw)
                        patch_collect.add(json.dumps(patch))

            # 记录sink信息
            vul_info = {}
            vul_info['key'] = store_key
            vul_info['vulType'] = sink.vulType
            vul_info['entry'] = ';'.join(normalInfo[:entry_depth])
            vul_info['existWakeup'] = pop_dict[self.cur_key].wakeupExist
            vul_info['sink'] = sink.sinkLineNo
            vul_info['possibleJmpStack'] = possibleInfo
            vul_info['funcStack'] = normalInfo
            vul_info['callStack'] = callsiteInfo

            with open(result_file, 'a', encoding='utf8') as fw:
                print(json.dumps(vul_info, ensure_ascii=False), end='', file=fw)
                print(file=fw)

            find_num += 1

            # 记录当前时间
            info_log(time.time())
            print(json.dumps(vul_info, ensure_ascii=False))

    def wakeup_get_attr(self):
        '''
        在wakeup suggest时获取对应的属性名
        '''
        attr = '$this'
        for jmp in pop_dict[self.cur_key].firstJmpIndex:
            tp, key = jmp.split(':')
            if tp == 'attr':
                attr += '->'+key
            elif tp == 'key':
                attr += '["'+key+'"]'
            return attr

    def wakeup_suggest(self):
        '''
        出现无法修复的链时，对wakeup修复进行建议
        '''

        if pop_dict[self.cur_key].firstJmpIndex:
            suggest = f"{self.wakeup_get_attr()} = NULL;"
        else:
            suggest = 'die();'

        classname, methodname = pop_dict[self.cur_key].normalInfo[0].split('#')
        if '__wakeup' in class_dict[classname]:
            wakeup = class_dict[classname]['__wakeup']
            return [f"Suggestion: add \"{suggest}\" to the the __wakeup:", wakeup.sourcefile, wakeup.lineno, classname]
        else:
            for tmp in class_dict[classname]:
                return [f"Suggestion: add \"public function __wakeup(){{{suggest}}}\" to the class:", class_dict[classname][tmp].sourcefile, classname]

    def push_condition_rec(self, cond_node):
        '''
        递归地获取instanceof过滤的对象，并压栈
        '''
        global condition_stack
        if type(cond_node) == phpast.UnaryOp:
            self.push_condition_rec(cond_node.expr)
        elif type(cond_node) == phpast.BinaryOp:
            if cond_node.op == 'instanceof':
                inst = self.execute_ast(cond_node.left)
                if type(inst) == ControllableInstance:
                    condition_stack[-1].add(str(inst.index))
            else:
                self.push_condition_rec(cond_node.left)
                self.push_condition_rec(cond_node.right)
        elif type(cond_node) == phpast.FunctionCall:
            if cond_node.name in ('in_array', '\in_array'):
                tmp = self.execute_ast(cond_node.params[0].node)
                if type(tmp) == ControllableInstance:
                    condition_stack[-1].add(str(tmp.index))
            elif cond_node.name in ('is_array', '\is_array'):
                tmp = self.execute_ast(cond_node.params[0].node)
                if type(tmp) == ControllableInstance:
                    condition_stack[-1].add(str(tmp.index))

    def check_in_cond(self, index):
        '''
        检查index是否在条件过滤栈中
        '''
        global condition_stack

        res = False
        ind_str = str(index)
        for cond_set in condition_stack:
            if ind_str in cond_set:
                res = True

        return res

    def check_local_var_ctrl(self):
        '''
        校验当前所有局部变量的root是否为当前key对应的root
        由于ast的嵌套性和pop链并行执行需要复制上下文，很容易出现不匹配的情况
        一般在ast节点执行后打点，触发断点时按照报的不吻合变量名向外层寻找赋值处（由于嵌套性，很可能在外n层）
        赋值处真正的执行点在断点前，无法直接定位
        '''
        for varname in self.local_var:
            if type(self.local_var[varname]) == ControllableInstance:
                controllable = self.local_var[varname]
                root_ctrl = None
                try:
                    root_ctrl = self.get_inner_inst(
                        controllable.index)  # 获取root下对应的可控对象
                except Exception:
                    pass

                # 当前对象和root下的对象不是同一个可控对象
                if not (controllable is root_ctrl) and type(root_ctrl) == ControllableInstance:
                    print('局部变量与root不吻合：', varname, controllable.index)

                    for key in pop_dict:
                        try:
                            if self.get_inner_inst(controllable.index, target_inst=pop_dict[key].root) is controllable:
                                print(f'当前key：{self.cur_key}，局部变量key：{key}')
                        except Exception:
                            # print('无法获取当前key对应的receiver')
                            pass

                    print()

    def check_ctrl_in_root(self, controllable, root):
        '''
        校验controllable是否在当前root中
        '''
        try:
            root_ctrl = self.get_inner_inst(
                controllable.index, target_inst=root)
        except Exception:
            return False
        return root_ctrl is controllable

    def execute_ast(self, node):
        '''
        在AST上模拟执行
        如果发现危险函数调用，则记录该POP链
        sink检测结果不影响模拟执行过程，互相独立进行

        传入：
        node：当前ast结点

        传出：
        返回值，由于AST结点的特殊性，所有包含多执行的node，都需要优先返回Return类型的返回值
        '''

        # self.check_local_var_ctrl()

        global attr_func_dict, global_func_dict, class_dict
        global pop_dict, find_num
        global condition_stack

        ret_val = None  # 返回值

        # 是否达到同入口数量上限
        # summary模式需要限制possibleInfo等于1，否则提前终止导致summary不完全
        if (use_pm_summary and len(pop_dict[self.cur_key].possibleInfo) == 1) or not use_pm_summary:
            if len(pop_dict[self.cur_key].normalInfo) >= entry_depth:
                entry_func = pop_dict[self.cur_key].normalInfo[:entry_depth]
                entry_func = ';'.join(entry_func)
                if entry_func in entry_found_popnum:
                    if entry_found_popnum[entry_func] >= each_entry_early_stop_num:
                        return ret_val

        # 是否达到总数量上限
        if find_num >= early_stop_num:
            return ret_val

        # 是否达到链长度上限
        if len(pop_dict[self.cur_key].normalInfo) > max_normal_length:
            return ret_val

        # 是否达到PM链长度上限
        if len(pop_dict[self.cur_key].possibleInfo) > max_pm_length:
            return ret_val

        # AST模拟执行

        try:
            # 基本元素
            if type(node) == str:
                return node
            elif type(node) == int:
                return node
            elif type(node) == float:
                return node

            # list
            # 迭代执行
            elif type(node) == list:
                for vnode in node:
                    ret = self.execute_ast(vnode)
                    if type(ret_val) == ReturnValue:  # ret_val已有值，根据情况保留
                        if type(ret_val.val) == ControllableInstance:  # 贪心法
                            continue
                        elif type(ret) == ReturnValue:
                            # 既有True又有False
                            if (ret_val.val == True and ret.val == False) or (ret_val.val == False and ret.val == True):
                                ret_val = ReturnValue(None)
                            else:  # 否则用当前执行结果代替之前的结果
                                ret_val = ret
                    elif type(ret) == ReturnValue:  # ret_val没有赋值，list仅收集返回值的情况
                        ret_val = ret

            # Block
            # 贪心法
            elif type(node) == phpast.Block:
                for vexpr in node.nodes:  # 迭代执行
                    ret = self.execute_ast(vexpr)
                    # 贪心法
                    if type(ret_val) == ReturnValue and type(ret_val.val) == ControllableInstance:
                        pass
                    # list仅收集返回值的情况
                    elif type(ret) == ReturnValue:
                        ret_val = ret

            elif type(node) == phpast.Variable:

                if type(node.name) == str:  # 最后一层
                    return self.local_var[node.name[1:]]  # 去掉$号

                else:  # 递归解析
                    return self.local_var[self.execute_ast(node.name)]

            elif type(node) == phpast.Array:
                tmp_arr = PHPArray()

                if len(node.nodes) > 0:
                    for vnode in node.nodes:
                        # 无key值
                        if vnode.key == None:
                            tmp_arr.append(self.execute_ast(vnode.value))
                        # 有key值
                        else:
                            tmpkey = self.execute_ast(vnode.key)
                            tmp_arr[tmpkey] = self.execute_ast(vnode.value)

                return tmp_arr

            elif type(node) == phpast.ArrayElement:
                print('ArrayElement')

            elif type(node) == phpast.ArrayOffset:  # 获取数组元素

                tmp_arr = self.execute_ast(
                    node.node)
                offset = self.execute_ast(node.expr)

                if offset in (None, 'DONTCARE'):
                    if type(tmp_arr) == ControllableInstance or (type(tmp_arr) == PHPArray and tmp_arr.isControllable):
                        pass
                    else:
                        return ret_val

                # 数组的offset只能是字符串或int
                if type(offset) == ControllableInstance and offset.classname == None:
                    offset = self.controllable_assign(offset, source_token)

                if type(tmp_arr) == ControllableInstance and tmp_arr.classname == None:  # 可控对象
                    # ArrayAccess
                    tnode = ArrayAccessNode(node.node)
                    self.call_implement_methods(
                        tmp_arr, '!arrayaccess-get', [], tnode)
                    tmp_arr = self.controllable_arr_assign(tmp_arr, offset)
                    if tmp_arr in (None, 'DONTCARE'):
                        return None
                    return tmp_arr[offset]
                elif type(tmp_arr) == PHPArray and tmp_arr.isControllable:  # 可控数组
                    # ArrayAccess
                    if not tmp_arr.isSanitized:
                        tnode = ArrayAccessNode(node.node)
                        self.call_implement_methods(
                            tmp_arr, '!arrayaccess-get', [], tnode)
                    tmp_ctrl = ControllableInstance()
                    tmp_ctrl.index = copy.copy(tmp_arr.index)
                    tmp_ctrl.index.append(f'key:{offset}')
                    tmp_arr[offset] = tmp_ctrl
                    return tmp_arr[offset]
                else:  # 一般情况
                    if type(tmp_arr) == PHPArray and offset in tmp_arr:
                        return tmp_arr[offset]

            # 赋值语句
            # 普通赋值、this->xxx->xxx=xxx和this->xxx=xxx的处理、__set的处理
            elif type(node) == phpast.Assignment:
                val = self.execute_ast(node.expr)
                var = self.get_varref(node.node, True)
                ret_val = val

                if var in (None, 'NOTFOUND') or var.ref == None or type(var.ref) == str or var.key == None:  # 不关心的赋值
                    return ret_val

                base = None
                if type(node.node) == phpast.ObjectProperty:  # 属性赋值
                    base = self.execute_ast(node.node.node)

                # base可控，并且base未被赋值为具体类，触发__set
                if type(base) == ControllableInstance and base.classname == None:
                    attrname = self.execute_ast(node.node.name)
                    # __set参数为$attrname, $value
                    self.call_possible_methods(
                        base, '__set', [attrname, val], node)

                # 一般情况
                else:
                    #  前一层的key为可控对象（还未赋值），比如 arr[$this->a] = xxx;
                    #  直接把$this->a赋值为任意值
                    if type(var.key) == ControllableInstance and var.key.classname == None:
                        self.controllable_assign(var.key, source_token)
                        var.key = source_token

                    # 贪心法，保护if、catch分支中的可控变量被覆盖
                    if hasattr(node, 'parent') and var.key != None:
                        # if
                        if type(var.ref[var.key]) == ControllableInstance or \
                            (type(var.ref[var.key]) == str and source_token in var.ref[var.key]) or \
                                (type(val) == str and val != source_token):
                            if hasattr(node.parent, 'parent') and type(node.parent.parent) in (phpast.If, phpast.ElseIf, phpast.Else):
                                return ret_val
                        # catch
                        if type(node.parent) == phpast.Catch:
                            if val == None:
                                return ret_val

                        # foreach
                        if hasattr(node.parent, 'parent') and type(node.parent.parent) == phpast.Foreach:
                            if val == None:
                                return ret_val

                    # 赋值，贪心法，不覆盖可控对象
                    if type(var.ref[var.key]) != ControllableInstance:
                        var.setValue(val)
                    else:  # 否则仅在if作用域里过滤
                        condition_stack[-1].add(str(var.ref[var.key].index))

                return ret_val

            # If
            elif type(node) == phpast.If:
                condition = self.execute_ast(node.expr)  # 条件的运算在新栈建立前
                if condition != True:  # 当条件运算恒真时，将不再存在if隔离
                    condition_stack.append(set())
                self.push_condition_rec(node.expr)
                # 如果确认条件为false则不执行if
                if condition == False:
                    pass
                else:
                    ret_val = self.execute_ast(node.node)
                if condition != True:
                    condition_stack.pop()  # 还原条件栈
                # 如果确认条件为true则不执行elseif和else
                if condition == True:
                    pass
                else:
                    for elseif in node.elseifs:
                        condition = self.execute_ast(elseif.expr)
                        if condition != True:  # 当条件运算恒真时，将不再存在if隔离
                            condition_stack.append(set())
                        self.push_condition_rec(elseif.expr)
                        # 如果确认条件为false则不执行
                        if condition == False:
                            pass
                        else:
                            # 贪心法
                            tmp_ret = self.execute_ast(elseif.node)
                            if type(ret_val) == ReturnValue and type(ret_val.val) == ControllableInstance:
                                pass
                            else:
                                ret_val = tmp_ret
                        if condition != True:
                            condition_stack.pop()  # 还原条件栈
                    else_ = node.else_
                    if else_ != None:
                        # 贪心法
                        tmp_ret = self.execute_ast(else_.node)
                        if type(ret_val) == ReturnValue and type(ret_val.val) == ControllableInstance:
                            pass
                        else:
                            ret_val = tmp_ret

            #  while
            elif type(node) == phpast.While:
                expr = []
                expr.append(node.expr)
                expr += node.node.nodes

                for vexpr in expr:  # 迭代每个结点
                    ret = self.execute_ast(vexpr)
                    if type(ret) == ReturnValue:  # 优先收集返回值
                        ret_val = ret

            # DoWhile
            elif type(node) == phpast.DoWhile:
                expr = []
                expr.append(node.expr)
                expr += node.node.nodes

                for vexpr in expr:  # 迭代每个结点
                    ret = self.execute_ast(vexpr)
                    if type(ret) == ReturnValue:  # 优先收集返回值
                        ret_val = ret

            # Switch
            elif type(node) == phpast.Switch:
                expr = []
                expr.append(node.expr)
                expr += node.nodes

                for vexpr in expr:  # 迭代每个结点
                    ret = self.execute_ast(vexpr)
                    if type(ret) == ReturnValue:  # 优先收集返回值
                        ret_val = ret

            # For
            elif type(node) == phpast.For:
                # 对for的执行体进行递归寻找
                ret_val = self.execute_ast(node.node)

            # Foreach
            elif type(node) == phpast.Foreach:
                arr = self.execute_ast(node.expr)
                # 对iteratoraggregate特殊接口进行处理
                if hasattr(arr, 'classname'):
                    if arr.classname in class_dict and '!iteratoraggregate' in class_dict[arr.classname]:
                        arr = self.call_method(arr, 'getIterator', [], node)
                arr_len = 0
                if type(arr) in (ControllableInstance, PHPArray):
                    if node.keyvar != None:  # 取key时
                        keyvar = node.keyvar.name[1:]
                        valvar = node.valvar.name.name[1:]
                        if (type(arr) == ControllableInstance and arr.classname == None) or (type(arr) == PHPArray and arr.isControllable):
                            if not node.valvar.is_ref:  # 引用时不触发iterator
                                # Iterator
                                tnode = IteratorNode(node.expr)
                                self.call_implement_methods(
                                    arr, '!iterator', [], tnode)

                            offset = source_token
                            arr = self.controllable_arr_assign(arr, offset)

                        # php的数组比较特殊，即可表达数组也可表达字典
                        if type(arr) == PHPArray:
                            if arr.isControllable and len(arr) == 0:
                                tmp = arr[source_token]

                            for keyval in arr:  # 获取第一个元素
                                valval = arr[keyval]
                                break
                        else:
                            return ret_val

                        if len(arr) > 0:
                            self.local_var[keyvar] = keyval
                            self.local_var[valvar] = valval
                            arr_len = 1

                    else:  # 不取key时
                        if (type(arr) == ControllableInstance and arr.classname == None) or (type(arr) == PHPArray and arr.isControllable):
                            if not node.valvar.is_ref:  # 引用时不触发iterator
                                # Iterator
                                tnode = IteratorNode(node.expr)
                                self.call_implement_methods(
                                    arr, '!iterator', [], tnode)
                            arr = self.controllable_arr_assign(arr, 0)

                        if type(arr) != PHPArray:
                            return ret_val

                        if arr.isControllable and len(arr) == 0:
                            tmp = arr[0]

                        valvar = node.valvar.name.name[1:]
                        if len(arr) > 0:
                            for vkey in arr:
                                self.local_var[valvar] = arr[vkey]
                            arr_len = 1

                # if arr_len > 0:
                # 对foreach的执行体进行递归寻找
                ret_val = self.execute_ast(node.node)

            elif type(node) == phpast.Function:
                ret_val = self.execute_ast(node.nodes)

            elif type(node) == phpast.Method:
                ret_val = self.execute_ast(node.nodes)

            elif type(node) == phpast.Eval:
                # check sink
                expr = self.execute_ast(node.expr)
                expr = self.tostr(expr, node.expr)
                if 'SOURCE_TOKEN' in expr:
                    self.pop_log_report('EVAL命令执行(Eval code execution)', node)

            elif type(node) == phpast.Include:
                # check sink
                expr = self.execute_ast(node.expr)
                if 'SOURCE_TOKEN' in expr:
                    self.pop_log_report('文件包含(File inclusion)', node)

            elif type(node) == phpast.Require:
                # check sink
                expr = self.execute_ast(node.expr)
                if 'SOURCE_TOKEN' in expr:
                    self.pop_log_report('文件包含(File inclusion)', node)

            elif type(node) == phpast.Exit:
                condition_stack[-2].update(condition_stack[-1])  # 最后一层条件向上一层浮动
                # check sink
                echoed = self.tostr(self.execute_ast(node.expr), node.expr)
                if 'SOURCE_TOKEN' in echoed:  # XSS
                    self.pop_log_report('XSS', node)

            # 函数调用
            elif type(node) == phpast.FunctionCall:

                # 获取函数名
                funcname = self.execute_ast(node.name)

                # 获取参数
                par_li = []
                for vp in node.params:
                    par_li.append(self.execute_ast(vp.node))

                # call_user_func
                if funcname == 'call_user_func':
                    receiver = None
                    method = None

                    # call_user_func([$this, 'method'], xxx);
                    if type(par_li[0]) == PHPArray:
                        receiver = par_li[0][0]
                        method = par_li[0][1]
                        par_li = par_li[1:]

                    # call_user_func($this->attr, xxx);
                    elif type(par_li[0]) == ControllableInstance and par_li[0].classname == None:
                        self.pop_log_report(
                            '任意函数调用(Arbitrary function called)', node)
                        return ret_val

                    # call_user_func($this->method, xxx);
                    elif type(par_li[0]) == phpast.Method:
                        receiver = self.execute_ast(node.params[0].node.node)
                        method = node.params[0].node.name
                        par_li = par_li[1:]

                    # call_user_func('sprintf', xxx);
                    elif type(par_li[0]) == str:
                        return self.call_func(par_li[0], par_li[1:], node)

                    if type(receiver) == ControllableInstance and receiver.classname == None:
                        ret_val = self.call_possible_methods(
                            receiver, method, par_li, node)
                    else:
                        ret_val = self.call_method(
                            receiver, method, par_li, node)

                elif funcname == 'call_user_func_array':
                    receiver = None
                    method = None

                    # call_user_func_array([$this, 'method'], xxx);
                    if type(par_li[0]) == PHPArray:
                        receiver = par_li[0][0]
                        method = par_li[0][1]
                        par_li = par_li[1]

                    # call_user_func_array($this->attr, xxx);
                    elif type(par_li[0]) == ControllableInstance and par_li[0].classname == None:
                        self.pop_log_report(
                            '任意函数调用(Arbitrary function called)', node)
                        return ret_val

                    # call_user_func_array($this->method, xxx);
                    elif type(par_li[0]) == phpast.Method:
                        receiver = self.execute_ast(node.params[0].node.node)
                        method = node.params[0].node.name
                        par_li = par_li[1]

                    # call_user_func_array('sprintf', xxx);
                    elif type(par_li[0]) == str:
                        return self.call_func(par_li[0], par_li[1], node)

                    if type(par_li) == str:
                        par_li = []

                    if type(receiver) == ControllableInstance and receiver.classname == None:
                        # if type(receiver) == ControllableInstance:
                        ret_val = self.call_possible_methods(
                            receiver, method, par_li, node)
                    else:
                        ret_val = self.call_method(
                            receiver, method, par_li, node)

                elif type(funcname) == ControllableInstance:  # __invoke
                    self.pop_log_report(
                        '任意函数调用(Arbitrary function called)', node)
                    ret_val = self.call_possible_methods(
                        funcname, '__invoke', par_li, node)

                else:  # 普通的函数调用
                    ret_val = self.call_func(funcname, par_li, node)

            # 方法调用
            elif type(node) == phpast.MethodCall:

                # 获取参数，由于该过程可能会影响receiver，所以先获取参数再获取receiver
                par_li = []
                for vp in node.params:
                    if type(vp.node) == phpast.UnaryOp and vp.node.op == '...':  # ...操作
                        par_li = self.execute_ast(vp.node.expr)
                        break
                    else:
                        par_li.append(self.execute_ast(vp.node))

                receiver = self.execute_ast(node.node)
                methodname = self.execute_ast(node.name)

                # 可控对象，并且没有明确类名，触发方法寻找
                if type(receiver) == ControllableInstance and receiver.classname == None:
                    ret_val = self.call_possible_methods(
                        receiver, methodname, par_li, node)

                # 一般对象
                elif type(receiver) == PHPInstance or type(receiver) == ControllableInstance:
                    return self.call_method(receiver, methodname, par_li, node)

            # Echo
            elif type(node) == phpast.Echo:
                # check sink
                for vexpr in node.nodes:  # 迭代执行，并且字符串化
                    echoed = self.tostr(self.execute_ast(vexpr), vexpr)
                    if 'SOURCE_TOKEN' in echoed:  # XSS
                        self.pop_log_report('XSS', node)

            # Print
            elif type(node) == phpast.Print:
                echoed = self.tostr(self.execute_ast(node.node), node.node)
                if 'SOURCE_TOKEN' in echoed:  # XSS
                    self.pop_log_report('XSS', node)

            # Return
            elif type(node) == phpast.Return:
                cond_offset = len(condition_stack) - 1
                func_offset = cond_stack_depth[-1] - 1
                # 确保存在if层，而不是直接在函数调用层上浮，否则上浮的作用域过大
                if cond_offset > func_offset:
                    condition_stack[cond_offset -
                                    1].update(condition_stack[cond_offset])  # 最后一层条件向上一层浮动
                ret_val = ReturnValue(self.execute_ast(node.node))

            # isset(this->xxx->xxx)的处理（跳转去__isset）
            elif type(node) == phpast.IsSet:

                for inner_node in node.nodes:

                    if type(inner_node) == phpast.ObjectProperty:  # 只处理获取属性的语句

                        inst = self.execute_ast(inner_node.node)
                        attrname = self.execute_ast(inner_node.name)

                        # 可控对象，并且没有具体类名，说明可以任意赋值，可以触发__isset
                        if type(inst) == ControllableInstance and inst.classname == None:
                            # if type(inst) == ControllableInstance:

                            self.call_possible_methods(
                                inst, '__isset', [attrname], node)  # __isset的参数为属性名

            # unset(this->xxx->xxx)的处理（跳转去__unset）
            elif type(node) == phpast.Unset:

                for inner_node in node.nodes:

                    if type(inner_node) == phpast.ObjectProperty:  # 只处理获取属性的语句

                        inst = self.execute_ast(inner_node.node)
                        attrname = self.execute_ast(inner_node.name)

                        # 可控对象，并且没有具体类名，说明可以任意赋值，可以触发__unset
                        if type(inst) == ControllableInstance and inst.classname == None:
                            # if type(inst) == ControllableInstance:

                            self.call_possible_methods(
                                inst, '__unset', [attrname], node)  # __unset的参数为属性名

            # this->xxx->xxx和this->xxx的处理 （__get）
            elif type(node) == phpast.ObjectProperty:

                inst = self.execute_ast(node.node)
                attrname = self.execute_ast(node.name)

                if type(inst) == str:
                    return 'DONTCARE'

                if type(attrname) == ControllableInstance and attrname.classname == None:
                    attrname = self.controllable_assign(attrname, source_token)

                if attrname == None:
                    attrname = 'NOTFOUND'

                if type(inst) == ControllableInstance:  # 可控对象，属性可以任意赋值
                    if inst.classname != None:  # 已有类名，不触发__get
                        if '$'+attrname in class_dict[inst.classname]:
                            # 静态类属性不可控
                            if 'static' in class_dict[inst.classname]['$'+attrname].parent.modifiers:
                                return 'DONTCARE'

                        if attrname not in inst.attr:  # 没有赋值时
                            # 生成新的可控对象
                            inst.attr[attrname] = ControllableInstance()
                            # 记录root index
                            tmp_index = copy.copy(inst.index)
                            tmp_index.append('attr:'+attrname)
                            inst.attr[attrname].index = tmp_index

                        ret_val = inst.attr[attrname]

                    else:  # 没有具体类名，说明可以任意赋值，可以触发__get
                        self.call_possible_methods(
                            inst, '__get', [attrname], node)  # __get的参数为属性名

                        # 除了调用__get，也可以生成新的可控对象
                        # 这里的逻辑相当于并行执行了__get和返回任意一个对象，不遵循一般的ast执行
                        # 原理是考虑到__get有效返回值的情况可以被返回可控变量覆盖到，同时也是为了能够触发toString
                        inst.attr[attrname] = ControllableInstance()

                        # 记录root index
                        tmp_index = copy.copy(inst.index)
                        tmp_index.append('attr:'+attrname)
                        inst.attr[attrname].index = tmp_index

                        ret_val = inst.attr[attrname]

                # 一般的成员属性
                elif type(inst) == PHPInstance and attrname in inst.attr:
                    ret_val = inst.attr[attrname]

                # 成员属性/方法
                else:

                    if attrname == None:
                        return ret_val

                    if inst == None:
                        return ret_val

                    # 不存在该属性
                    if '$'+attrname not in class_dict[inst.classname]:
                        return 'NOTFOUND'

                    tmp = class_dict[inst.classname]['$'+attrname]

                    # 成员属性
                    if type(tmp) == phpast.ClassVariable:
                        inst.attr[attrname] = 'NOTFOUND'
                        ret_val = inst.attr[attrname]

                    # 成员方法
                    else:
                        ret_val = tmp

            # AssignOp  += -= ...
            elif type(node) == phpast.AssignOp:
                if node.op == '.=':
                    var = self.get_varref(node.left, True)
                    var_t = self.execute_ast(node.left)
                    val = self.execute_ast(node.right)
                    val = self.tostr(var_t, node.left) + \
                        self.tostr(val, node.right)
                    if var in (None, 'NOTFOUND') or var.ref == None or type(var.ref) == str or var.key == None:  # 不关心的赋值
                        return ret_val
                    # 赋值，贪心法，不覆盖可控对象
                    if type(var.ref[var.key]) != ControllableInstance:
                        var.setValue(val)
                    else:  # 否则仅在if作用域里过滤
                        condition_stack[-1].add(str(var.ref[var.key].index))
                    return ret_val
                else:
                    right = self.execute_ast(node.right)

            # UnaryOp  -xx +xx ...
            elif type(node) == phpast.UnaryOp:
                tmp = self.execute_ast(node.expr)
                if node.op == '-':
                    ret_val = -tmp

            # BinaryOp xx >= xx
            elif type(node) == phpast.BinaryOp:

                # 字符串拼接，先执行拼接的两个表达式，再分别调用tostr，最后拼接
                if node.op == '.':
                    left = self.execute_ast(node.left)
                    right = self.execute_ast(node.right)
                    ret_val = self.tostr(left, node.left) + \
                        self.tostr(right, node.right)

                # 双问号
                elif node.op == '??':
                    left = self.execute_ast(node.left)
                    right = self.execute_ast(node.right)

                    # 贪心法
                    if left == None:
                        return right
                    elif 'ControllableInstance' in str(left):
                        return left
                    elif 'ControllableInstance' in str(right):
                        return right
                    else:
                        return left

                # 值对比
                elif node.op in ('==', '==='):
                    left = self.execute_ast(node.left)
                    right = self.execute_ast(node.right)

                    if left not in (None, 'NOTFOUND', 'DONTCARE') and right not in (None, 'NOTFOUND', 'DONTCARE'):
                        # 当前仅判断str的情况
                        if type(left) == str and type(right) == str:
                            ret_val = left == right

                # 对instanceof的处理
                elif node.op == 'instanceof':
                    inst = self.execute_ast(node.left)
                    if type(inst) == ControllableInstance:
                        if type(node.right) == phpast.Constant:
                            if node.right.name in ('iterator', 'arrayaccess'):
                                tarr = PHPArray()
                                tarr.isControllable = True
                                tarr.index = inst.index
                                tarr.isSanitized = True
                                self.controllable_assign(inst, tarr)
                elif node.op == '&&':
                    lres = self.execute_ast(node.left)
                    if lres == False:
                        ret_val = lres
                    else:
                        ret_val = self.execute_ast(node.right)
                else:  # 其他情况
                    expr = [node.left, node.right]
                    for vexpr in expr:  # 迭代执行
                        self.execute_ast(vexpr)

            # TernaryOp
            elif type(node) == phpast.TernaryOp:

                cond = self.execute_ast(node.expr)
                true_ret = None
                false_ret = None
                if cond == True:
                    true_ret = self.execute_ast(node.iftrue)
                elif cond == False:
                    false_ret = self.execute_ast(node.iffalse)
                else:
                    true_ret = self.execute_ast(node.iftrue)
                    false_ret = self.execute_ast(node.iffalse)

                # 贪心法
                if false_ret == None:
                    return true_ret
                elif 'ControllableInstance' in str(true_ret):
                    return true_ret
                elif 'ControllableInstance' in str(false_ret):
                    return false_ret
                else:
                    return true_ret

            elif type(node) == phpast.ListAssignment:
                arr = self.execute_ast(node.expr)
                if type(arr) == PHPArray:
                    for i in range(len(node.nodes)):
                        # 获取变量ref并赋值
                        var = self.get_varref(node.nodes[i])
                        var.setValue(arr[i])
                elif type(arr) == ControllableInstance and arr.classname == None:
                    arr = self.controllable_arr_assign(arr, 0)
                    var = self.get_varref(node.nodes[0])
                    var.setValue(arr[0])
                    for i in range(1, len(node.nodes)):
                        arr[i] = ControllableInstance()
                        # 记录root index
                        tmp_index = copy.copy(arr.index)
                        tmp_index.append(f'key:{i}')
                        arr[i].index = tmp_index
                        # 获取变量ref并赋值
                        var = self.get_varref(node.nodes[i])
                        var.setValue(arr[i])

            elif type(node) == phpast.New:
                # 先找到类，创建一个PHPInstance作为返回值，之后调用该类的构造函数（如果有的话）
                # 1. use_list 2. 添加反斜杠 3. 添加namespace
                classname = self.execute_ast(node.name)
                # if type(classname) == str:
                #     classname = classname.lower()
                if type(classname) not in (ControllableInstance, str):
                    return ret_val

                # \\ArrayIterator内置类特殊处理（这里仅简化处理
                if classname == '\\ArrayIterator':
                    return self.execute_ast(node.params[0].node)

                # 构造函数第一个参数触发字符串化的情况
                if classname in class_dict and '!construct_tostr' in class_dict[classname]:
                    tmp = self.execute_ast(node.params[0].node)
                    self.tostr(tmp, node.params[0].node)

                if type(classname) == ControllableInstance and classname.classname != None:
                    return ret_val

                if classname == 'static':
                    classname = self.local_var['this'].classname

                inst = None

                # 类名可控
                if type(classname) == ControllableInstance and classname.classname == None:
                    par_li = []
                    # 获取参数
                    for vp in node.params:
                        par_li.append(self.execute_ast(vp.node))

                    # 构造函数的类名可控的情况，难以进行完整的静态分析，仅直接报sink
                    # self.pop_log_report(
                    #     '任意类构造函数调用(Arbitrary constructor called)', node)

                    self.controllable_assign(classname, source_token)

                # 完整的命名空间
                elif '\\' in classname:
                    inst = PHPInstance(classname)

                # 没有加命名空间
                else:
                    if classname in BuiltinClass:  # 内置类，不关注
                        inst = None
                    elif classname in self.use_list:  # 在use列表中
                        inst = PHPInstance(self.use_list[classname])
                    elif self.namespace+'\\' + classname in class_dict:  # 省略了命名空间
                        inst = PHPInstance(self.namespace+'\\' + classname)

                if inst == None:
                    return 'DONTCARE'

                if inst.classname not in class_dict:  # 未找到目标类
                    return 'DONTCARE'

                if '__construct' in class_dict[inst.classname]:  # 尝试调用构造函数
                    par_li = []
                    # 获取参数
                    for vp in node.params:
                        par_li.append(self.execute_ast(vp.node))

                    self.call_method(inst, '__construct',
                                     par_li, node)  # 调用构造函数

                return inst

            # 命名空间
            elif type(node) == phpast.Namespace:
                if node.name != None:
                    self.namespace = node.name

            elif type(node) == phpast.Clone:
                # 虽然是clone，由于pop链问题的特殊性，需要对原root进行修改，所以这里直接返回原值
                # return copy.deepcopy(self.execute_ast(node.node))
                return self.execute_ast(node.node)

            # 暂不处理
            elif type(node) == phpast.Break:
                pass

            # 暂不处理
            elif type(node) == phpast.Continue:
                pass

            elif type(node) == phpast.Yield:
                print('Yield', f'''"{node.sourcefile}", line {node.lineno}''')

            elif type(node) == phpast.YieldFrom:
                print('YieldFrom',
                      f'''"{node.sourcefile}", line {node.lineno}''')

            elif type(node) == phpast.Global:  # 暂不处理全局变量
                pass

            elif type(node) == phpast.Static:
                for vnode in node.nodes:
                    self.execute_ast(vnode)

            elif type(node) == phpast.Try:
                ret_val = self.execute_ast(node.nodes)
                for catch in node.catches:
                    self.execute_ast(catch.nodes)

            elif type(node) == phpast.Catch:
                print('Catch')

            elif type(node) == phpast.Finally:
                print('Finally')

            elif type(node) == phpast.Throw:
                condition_stack[-2].update(condition_stack[-1])
                self.execute_ast(node.node)

            elif type(node) == phpast.Declare:
                print(
                    'Declare', f'''"{node.sourcefile}", line {node.lineno}''')

            elif type(node) == phpast.Directive:
                print('Directive',
                      f'''"{node.sourcefile}", line {node.lineno}''')

            elif type(node) == phpast.Closure:
                return node  # 直接返回整个匿名函数

            elif type(node) == phpast.Class:
                print('Class', f'''"{node.sourcefile}", line {node.lineno}''')

            elif type(node) == phpast.Trait:
                print('Trait', f'''"{node.sourcefile}", line {node.lineno}''')

            elif type(node) == phpast.ClassConstants:
                print('ClassConstants')

            elif type(node) == phpast.ClassConstant:
                print('ClassConstant')

            elif type(node) == phpast.ClassVariables:
                print('ClassVariables')

            elif type(node) == phpast.ClassVariable:
                print('ClassVariable')

            elif type(node) == phpast.Interface:
                print('Interface')

            # 暂不处理自增减
            elif type(node) == phpast.PreIncDecOp:
                pass

            # 暂不处理自增减
            elif type(node) == phpast.PostIncDecOp:
                pass

            elif type(node) == phpast.Cast:
                tmp = self.execute_ast(node.expr)
                if node.type == 'string':
                    ret_val = self.tostr(tmp, node.expr)

            elif type(node) == phpast.Empty:
                self.execute_ast(node.expr)

            elif type(node) == phpast.Silence:
                return self.execute_ast(node.expr)

            # 先暂时返回常量名
            elif type(node) == phpast.MagicConstant:
                return node.name

            elif type(node) == phpast.Constant:
                if node.name == 'false':
                    return False
                elif node.name == 'true':
                    return True
                elif node.name == 'null':
                    return None
                # 这里处理有一些问题，用常量名代替常量
                else:
                    return node.name

            # 暂不处理静态变量
            elif type(node) == phpast.StaticVariable:
                pass
                # print('StaticVariable')

            elif type(node) == phpast.LexicalVariable:
                print('LexicalVariable')

            elif type(node) == phpast.FormalParameter:
                print('FormalParameter')

            elif type(node) == phpast.Parameter:
                print('Parameter')

            # 暂时不关心字符串索引
            elif type(node) == phpast.StringOffset:
                return None

            # 暂不处理静态属性
            elif type(node) == phpast.StaticProperty:
                return None

            elif type(node) == phpast.StaticMethodCall:

                par_li = []
                # 获取参数
                for vp in node.params:
                    par_li.append(self.execute_ast(vp.node))

                vclassname = self.execute_ast(node.class_)

                if type(vclassname) == ControllableInstance:  # 不处理可控对象的静态方法调用
                    return ret_val

                if vclassname == 'self':
                    classname = self.local_var['this'].classname
                elif vclassname == 'parent':
                    return self.call_method('parent', node.name, par_li, node)
                elif vclassname in self.use_list:
                    classname = self.use_list[vclassname]
                elif '\\' in vclassname:
                    classname = vclassname
                else:
                    classname = self.namespace+'\\'+vclassname

                ret_val = self.call_static_method(
                    classname, node.name, par_li, node)

            elif type(node) == phpast.ElseIf:
                print('ElseIf')

            elif type(node) == phpast.Else:
                print('Else')

            elif type(node) == phpast.ForeachVariable:
                print('ForeachVariable')

            elif type(node) == phpast.Case:
                ret_val = self.execute_ast(node.nodes)

            elif type(node) == phpast.Default:
                ret_val = self.execute_ast(node.nodes)

            elif type(node) == phpast.UseDeclarations:
                print('UseDeclarations')

            elif type(node) == phpast.UseDeclaration:
                print('UseDeclaration')

            elif type(node) == phpast.ConstantDeclarations:
                print('ConstantDeclarations')

            elif type(node) == phpast.ConstantDeclaration:
                print('ConstantDeclaration')

            elif type(node) == phpast.TraitUse:
                print('TraitUse')

            elif type(node) == phpast.TraitModifier:
                print('TraitModifier')

        except Exception as e:
            pass
            # with open(log_file, 'a') as fw:
            #     print('[- error]', type(e),
            #           f'''"{node.sourcefile}", line {node.lineno}''', file=fw)
            # print(traceback.format_exc(), file=fw)

        # self.check_local_var_ctrl()
        return ret_val
