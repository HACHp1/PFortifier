from phply import phpast
from phply.phplex import lexer
from phply.phpparse import make_parser
import string
import random
from collections import OrderedDict
import os
from config import *
from POPChainHunter.BuiltinClass import *
from POPChainHunter.BuiltinInterface import *
import sys
import time
import pickle
import copy
import traceback
import signal


start_time = time.time()

sys.setrecursionlimit(python_rec_depth)

# ---- 全局变量与特殊变量的维护列表

# 源字符串

source_token = 'SOURCE_TOKEN'

# ---sink

# 代码执行

code_rce = [
    'array_map', 'create_function', 'call_user_func', 'call_user_func_array',
    'assert', 'dl', 'register_tick_function', 'register_shutdown_function',
]


# 系统命令注入

sys_rce = [
    'system',
    'exec',
    'passthru',
    'shell_exec',
    'pcntl_exec',
    'proc_open',
    'popen',
    'escapeshellcmd',
]

# sql注入

sqli_func = [
    'mysql_db_query', 'mysqli_query', 'pg_execute', 'pg_insert', 'pg_query', 'pg_select',
    'pg_update', 'sqlite_query', 'msql_query', 'mssql_query', 'odbc_exec',
    'fbsql_query', 'sybase_query', 'ibase_query', 'dbx_query', 'ingres_query',
    'ifx_query', 'oci_parse', 'sqlsrv_query', 'maxdb_query', 'db2_exec', 'sqlite_exec',
]

sqli_func2 = [
    'mysql_query',
]

# xss

xss_func = [
    'print_r', 'printf', 'vprintf', 'trigger_error',
    'user_error', 'odbc_result_all', 'ovrimos_result_all', 'ifx_htmltbl_result'
]

xss_expr = ["ECHO", "PRINT", "EXIT"]


# ssrf

ssrf_func = ['get_headers']


# 任意文件读取

file_read_func = [
    'show_source', 'highlight_file', 'file_get_contents', 'readfile',
    'fopen', 'file',
]

# 任意文件删除

file_del_func = [
    'unlink',
]

# 文件敏感操作1

file_sensitive_func1 = [
    'rmdir',
    'mkdir',
    'chmod',
    'chown',
    'chgrp',
    'touch',
]

# 文件敏感操作2

file_sensitive_func2 = [
    'copy',
    'rename',
    'link',
    'symlink',
]

# ----结束

pop_dict = {}

'''
储存POP链的详细信息，每条链对应一个随机数键值

{
    'key':POPInfo(
        .root
        .normalInfo [
            "类名:方法名",
            "完整函数名" # 同一个函数只调用一次
            ]
        .possibleInfo [
            "仅方法名(或impl):c（参数可控） n（参数不可控）...", # 同一个方法名（可以不同类），且可控参数相同，只调用一次
        ]
        ...
    )
}
'''

jmp_node = {}  # 储存异常的跳转语句

'''
{
    'key1': [node_ref1, node_ref2...]
}
'''

# 储存已找到的pop链数量
find_num = 0

# 收集去重的patch
patch_collect = set()

# 收集无法修复的链的入口
unable2patch_entry = set()

# 条件过滤栈，记录instaceof中的过滤；每一个set对应一层If
condition_stack = []

# 经过函数、方法调用时，储存条件过滤栈深度，以用于隔离return的情况
cond_stack_depth = []

attr_func_dict = {}
'''
根据成员方法名（或接口名）查找相应类的字典：

attr_func_dict = {
        '成员方法名':['完整类名1', '完整类名2'],
        '接口名':['完整类名1', '完整类名2'],
}
'''


global_func_dict = {}
'''
全局自定义函数的字典

global_func_dict = {
    '命名空间\\函数名':函数的实现,
    ...
}
'''

class_dict = {}
'''
详细记录所有类的字典，包括类属性和类方法的索引；
特别地，#开头的属性表示不可继承的特殊信息；!开头的属性表示可继承的特殊信息

class_dict={
    '命名空间1\\类1':{
        '#type':是否为抽象类或trait,
        '!iterator': 1,
        '!arrayaccess': 1,
        '成员属性名1':xxx,
        '成员方法名1':xxx...
    }
}
'''

cannot_unser = set()  # 记录不能反序列化的类
class_dict.update(BuiltinClass)  # 加载原生类
class_dict.update(BuiltinInterface)  # 加载内置接口

ext_dict = {}

'''
记录继承关系的字典

{
    '完整类名1':'完整类名2'...
}
'''

ext_dict.update(BuiltinClassExt)  # 加载内置类继承关系

impl_dict = {}

'''
记录接口继承/实现关系的字典

{
    '完整接口1/类1': ['完整接口2', ...]...
}
'''

impl_dict.update(BuiltinIntExtends)  # 加载内置接口关系

use_trait_dict = {}

'''
记录trait use关系的字典，与继承关系不同的是，use trait语句包含的信息更加复杂，所以
这里直接把use_list和traits记录下来

{
    '完整类名1': [namespace1, tree.use_list, tree.traits]...
    '完整trait2': [namespace2, tree.use_list, tree.traits]...
}
'''

entry_found_popnum = {}
'''
记录以每个入口为开端的POP链数量，防止在一个入口上查找的POP链过多

entry_found_popnum={
    '命名空间1\\类1->方法名1':pop链数量1,
    '命名空间2\\类2->方法名2':pop链数量2,
}
'''

pm_offset = {}
'''
记录PM调用时（兼容记录impl调用），当前执行栈中各调用栈、信息栈的offset，以便在发现sink时储存每个pm对应的summary
执行完后需要删除当前offset记录

pm_offset = {
    "xxx:cn": [
        normalInfo_offset,
        possibleInfo_offset,
        callsiteInfo_offset,
        jmpNode_offset
    ]
}
'''

pm_summary = {}
'''
记录发现sink时，当前链中各PM(或impl)的summary，每个PM对应一个PMSummary
只记录，不删除（基于假设：同一个PM key对应的执行结果只有一个）

pm_summary = {
    "xxx:cn" : PMSummary,
    "!arrayaccess:c" : PMSummary,
}
'''

filter_sink_dict = {}

'''
发现sink时，记录每个入口对应的sink链节

filter_sink_dict = {
    'entry1':set('sink1',...)
    ...
}
'''

# -----结束


def random_string(stringLength=10):
    '''
    随机产生一个字母组成的字符串
    '''
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(stringLength))


def clean_dir(dir):
    try:
        shutil.rmtree(dir)
    except FileNotFoundError:
        pass
    os.mkdir(dir)  # 清空文件夹


def info_log(cur_time):
    with open(info_file, 'w') as fw:
        fw.write('Scan target:\n')
        fw.write('php_prog_root: '+php_prog_root+'\n')
        fw.write('entry_depth: '+str(entry_depth)+'\n')
        fw.write('max_pm_length: '+str(max_pm_length)+'\n')
        fw.write('max_normal_length: '+str(max_normal_length)+'\n')
        fw.write('each_entry_early_stop_num: ' +
                 str(each_entry_early_stop_num)+'\n')

        for func in entry_func_li:
            if func not in attr_func_dict:
                continue
            fw.write('total entry('+func+') num: ' +
                     str(len(attr_func_dict[func]))+'\n')

        fw.write('Time spent: '+str(cur_time-start_time)+'(s)\n')


class POPInfo:
    '''
    记录POP链的详细信息
    - .root: ControllableInstance, # 记录pop链的根对象
    - .normalInfo: [], # 记录粗略的普通方法调用栈，用于防止无限递归
    - .possibleInfo: [], # 记录粗略的POP跳转调用栈，用于防止POP链路径爆炸
    - .callsiteInfo: ['', ''], # 记录调用点信息
    - .jmpNode,  # 在漏洞报告时储存跳转节点
    - .wakeupExist, # 入口类是否有wakeup
    - .firstJmpIndex, # 记录第一个跳转对应的root index，用于生成精准wakeup建议
    由于需要支持深拷贝，所有属性均不能包含"引用"，比如dict的引用
    '''

    def __init__(self, root):
        self.root = root
        self.normalInfo = []
        self.possibleInfo = []
        self.callsiteInfo = []
        self.jmpNode = None
        self.wakeupExist = False
        self.firstJmpIndex = None


class PHPArray:
    '''
    php数组比较奇葩，这里单独实现
    '''
    vdict = None
    vlist = None
    curIndex = -1  # curIndex只增不减（remove了也不会减）
    isControllable = False
    isSanitized = False  # 是否被过滤
    index = None  # 可控时储存index
    classname = None  # 可控时可以同时拥有类名

    def __init__(self, vdict=None):
        if vdict == None:
            self.vdict = OrderedDict()
        else:
            self.vdict = OrderedDict(vdict)

    def append(self, ele):
        self.curIndex += 1
        self.vdict[self.curIndex] = ele

    def remove(self, key):
        key = self.getInt(key)
        self.vdict.pop(key)

    def keys(self):
        return self.vdict.keys()

    def items(self):
        return self.vdict.items()

    def update(self, merged):
        self.vdict.update(merged)

    def __setitem__(self, key, value):
        key = self.getInt(key)
        if type(key) == int and key > self.curIndex:
            self.curIndex = key
        self.vdict[key] = value

    def __getitem__(self, key):
        key = self.getInt(key)
        if key in self.vdict:
            return self.vdict[key]
        elif self.isControllable:
            tmp_ele = ControllableInstance()
            key = self.getInt(key)
            if type(key) == int and key > self.curIndex:
                self.curIndex = key
            self.vdict[key] = tmp_ele
            # 记录root index
            tmp_index = copy.copy(self.index)
            tmp_index.append('key:{}'.format(key))
            tmp_ele.index = tmp_index
            return tmp_ele
        else:
            return 'NOTFOUND'

    def __delitem__(self, key):
        key = self.getInt(key)
        del self.vdict[key]

    def __len__(self):
        return len(self.vdict)

    def __contains__(self, key):
        key = self.getInt(key)
        return key in self.vdict

    def __iter__(self):
        return iter(self.vdict.keys())

    def getInt(self, key):
        try:
            ikey = int(key)
        except Exception:
            ikey = key
        return ikey

    def insertFirst(self, ele):
        self.append(ele)
        self.vdict.move_to_end(self.curIndex, last=False)


class PHPInstance:
    '''
    php对象模拟
    classname为包含名称空间的完整类名
    '''
    classname = ''  # 类名
    attr = None  # 属性

    def __init__(self, classname):
        self.classname = classname
        self.attr = {}


class LocalVarDict(dict):
    '''
    局部变量列表
    '''

    def __getitem__(self, key):

        if key in self:
            return super().__getitem__(key)

        else:  # 不存在时
            self[key] = 'NOTFOUND'
            return self[key]


class ControllableInstance(PHPInstance):
    '''
    可控的对象
    '''

    def __init__(self, classname=None):
        self.classname = classname
        self.attr = {}
        self.type = None
        self.sanitized = False
        self.isControllable = True  # 为了与PHPArray统一接口，增加此属性
        self.index = []  # 储存从根对象到当前对象的索引链 ['attr:xxx', 'key:xxx']


class VarRef:
    '''
    用来表示变量ref
    '''
    ref = None
    key = None

    def __init__(self, ref, key):
        self.ref = ref
        self.key = key

    def setValue(self, val):
        '''
        对ref进行赋值
        '''
        if type(self.ref) in (dict, LocalVarDict, PHPArray):
            if self.key != None:
                self.ref[self.key] = val
            # 数组赋值 $this->ClassObj['where'][$logic][] = xxx
            elif self.key == None and type(self.ref) == PHPArray:
                self.ref.append(val)


class ReturnValue:
    '''
    函数返回值
    '''
    val = None

    def __init__(self, val):
        self.val = val


class ToStringNode:
    '''
    储存触发toString的node，自动patch时用
    '''
    node = None

    def __init__(self, node):
        self.node = node

    def __getattr__(self, name):
        return self.node.__dict__[name]


class CallNode:
    '''
    调用__call的node
    '''
    node = None

    def __init__(self, node):
        self.node = node

    def __getattr__(self, name):
        return self.node.__dict__[name]


class IteratorNode:
    '''
    储存触发Iterator的node，自动patch时用
    '''
    node = None

    def __init__(self, node):
        self.node = node

    def __getattr__(self, name):
        # try:
        return self.node.__dict__[name]
        # except KeyError:
        #     print()


class ArrayAccessNode:
    '''
    储存触发ArrayAccess的node，自动patch时用
    '''
    node = None

    def __init__(self, node):
        self.node = node

    def __getattr__(self, name):
        # try:
        return self.node.__dict__[name]
        # except KeyError:
        #     print()


class PMSummary:
    '''
    PM（或impl）执行摘要，每个possible method call对应一个摘要

    - pm_depth ： 当前pm的深度
    - ret_val : 贪心法得到的返回值
    - assign_receiver : 贪心法得到的receiver类名
    - sinkInfo = [ SinkInfo1, SinkInfo2, ...] : 各sink点对应的信息，list组成
    '''
    pm_depth = None
    ret_val = None
    assign_receiver = None
    sinkInfo = None

    def __init__(self, pm_depth):
        self.sinkInfo = []
        self.pm_depth = pm_depth


class SinkInfo:
    '''
    储存pm对应的**单个**污点信息以及调用栈信息

    - normalInfo: [], # 普通方法调用栈
    - possibleInfo: [], # PM跳转调用栈
    - callsiteInfo: ['', ''], # 调用点信息
    - jmpNode,  # 跳转节点
    - vulType, # 漏洞类型
    - sinkLineNo, # sink代码位置
    '''
    normalInfo = None
    possibleInfo = None
    callsiteInfo = None
    jmpNode = None
    vulType = None
    sinkLineNo = None


def add_global_func(vfunction, namespace):
    '''
    将一个全局函数记录进全局变量中

    {
        '命名空间\\函数名':函数的实现,
    }
    '''
    global global_func_dict
    global_func_dict[namespace+'\\'+vfunction.name] = vfunction


def tree_global_func_dict(tree, namespace=''):
    '''
    递归进行树遍历，记录各全局函数
    '''

    # 如果是名称空间，则覆盖掉初始名称空间
    if type(tree) == phpast.Namespace and tree.name != None:
        namespace = tree.name

    # 如果本身就是全局函数
    if type(tree) == phpast.Function:
        tree.namespace = namespace  # 添加命名空间信息
        add_global_func(tree, namespace)
        return  # 全局函数不可能包含全局函数，直接返回

    # 单结点
    try:
        if type(tree.node) == phpast.Function:
            tree.node = namespace  # 添加命名空间信息
            tree_global_func_dict(tree.node, namespace)
            return  # 全局函数不可能内嵌全局函数，直接返回
    except AttributeError as e:
        pass

    # 多结点
    try:
        for node in tree.nodes:
            tree_global_func_dict(node, namespace)
    except AttributeError as e:
        pass


def add_class_attr(vclass, namespace, use_list):
    '''
    将一个类中的方法和属性都记录进全局变量中
    同时将类的use列表记录至方法
    '''
    global class_dict

    for node in vclass.nodes:  # 遍历类的每个成员
        if type(node) == phpast.ClassVariables:  # 类属性
            for attr in node.nodes:
                class_dict[namespace+'\\'+vclass.name
                           ][attr.name] = attr

        elif type(node) == phpast.ClassVariable:  # 单个类属性
            class_dict[namespace+'\\'+vclass.name
                       ][node.name] = node

        elif type(node) == phpast.Method:  # 类方法
            class_dict[namespace+'\\'+vclass.name][node.name] = node
            node.use_list = use_list  # 记录use列表

        elif type(node) == phpast.ClassConstants:  # ignore the CONST
            pass

        elif node == None:  # ignore None
            pass

        else:
            print('The attribute is not resolved: ', type(node))
            exit()


def add_trait_attr(trait, namespace, use_list):
    '''
    将一个trait中的方法和属性都记录进全局变量中
    同时将trait的use列表记录至方法
    '''
    global class_dict

    for node in trait.nodes:  # 遍历每个成员
        if type(node) == phpast.ClassVariables:  # 属性
            for attr in node.nodes:
                class_dict[namespace+'\\'+trait.name
                           ][attr.name] = attr

        elif type(node) == phpast.ClassVariable:  # 单个属性
            class_dict[namespace+'\\'+trait.name
                       ][node.name] = node

        elif type(node) == phpast.Method:  # 方法
            class_dict[namespace+'\\'+trait.name][node.name] = node
            node.use_list = use_list  # 记录use列表

        elif type(node) == phpast.ClassConstants:  # ignore the CONST
            pass

        elif node == None:  # ignore None
            pass

        else:
            print('The attribute is not resolved: ', type(node))
            exit()


def tree_set_class_dict(tree, namespace, sourcefile):
    '''
    递归进行树遍历，详细记录所有类的字典，包括类属性和类方法的索引；
    附加记录各节点的PHP源文件
    记录use列表
    记录继承关系
    记录父节点信息
    记录trait的属性、方法
    记录trait的use信息
    记录interface关系
    '''

    if tree == None:
        return

    # 设置源文件
    try:
        if tree.sourcefile == None:
            tree.sourcefile = sourcefile
    except AttributeError:
        pass

    # 如果是名称空间，则覆盖掉初始名称空间
    if type(tree) == phpast.Namespace and tree.name != None:
        namespace = tree.name

    # 如果本身就是类
    elif type(tree) == phpast.Class:

        class_dict[namespace+'\\'+tree.name] = {}
        # 记录类是否是抽象类
        if tree.type == 'abstract':
            class_dict[namespace+'\\'+tree.name]['#type'] = 'abstract'

        # 补全use列表
        if not hasattr(tree, 'use_list'):
            tree.use_list = {}

        # 记录继承关系
        if tree.extends:
            tmp_extends = tree.extends
            # 绝对路径
            if tmp_extends[0] == '\\':
                ext_class = tmp_extends
            # 相对路径
            else:
                # 首先尝试是否是use语句的类
                if tmp_extends in tree.use_list:
                    ext_class = tree.use_list[tmp_extends]
                    if '\\'+ext_class in BuiltinClass:
                        ext_class = '\\'+tmp_extends
                    elif '\\'+ext_class in class_dict:
                        ext_class = '\\'+tmp_extends
                # 内置类
                elif '\\'+tmp_extends in BuiltinClass:
                    ext_class = '\\'+tmp_extends
                # 省略根路径的名称
                elif '\\'+tmp_extends in class_dict:
                    ext_class = '\\'+tmp_extends
                else:
                    ext_class = namespace+'\\'+tmp_extends

            ext_dict[namespace+'\\'+tree.name] = ext_class

        # 记录use trait关系，由于当前还没解析完所有代码，这里先粗略地记录use关系
        if tree.traits:
            use_trait_dict[namespace+'\\' +
                           tree.name] = [namespace, tree.use_list, tree.traits]

        # 记录接口
        if tree.implements:
            tmp_impls = []
            for impl in tree.implements:
                # 绝对路径
                if impl[0] == '\\':
                    impl_int = impl
                # 相对路径
                else:
                    # 首先尝试是否是use语句的类
                    if impl in tree.use_list:
                        impl_int = tree.use_list[impl]
                        if '\\'+impl_int in BuiltinInterface:
                            impl_int = '\\'+impl_int
                        elif '\\'+impl_int in class_dict:
                            impl_int = '\\'+impl_int
                    # 内置类
                    elif '\\'+impl in BuiltinInterface:
                        impl_int = '\\'+impl
                    # 省略根路径的名称
                    elif '\\'+impl in class_dict:
                        impl_int = '\\'+impl
                    else:
                        impl_int = namespace+'\\'+impl
                tmp_impls.append(impl_int)
            impl_dict[namespace+'\\'+tree.name] = tmp_impls

        add_class_attr(tree, namespace, tree.use_list)

    # interface
    elif type(tree) == phpast.Interface:
        class_dict[namespace+'\\'+tree.name] = {}

        # 补全use列表
        if not hasattr(tree, 'use_list'):
            tree.use_list = {}

        # 记录继承关系
        if tree.extends:
            tmp_impls = []
            for impl in tree.extends:
                # 绝对路径
                if impl[0] == '\\':
                    impl_int = impl
                # 相对路径
                else:
                    # 首先尝试是否是use语句的类
                    if impl in tree.use_list:
                        impl_int = tree.use_list[impl]
                        if '\\'+impl_int in BuiltinInterface:
                            impl_int = '\\'+impl_int
                        elif '\\'+impl_int in class_dict:
                            impl_int = '\\'+impl_int
                    # 内置类
                    elif '\\'+impl in BuiltinInterface:
                        impl_int = '\\'+impl
                    # 省略根路径的名称
                    elif '\\'+impl in class_dict:
                        impl_int = '\\'+impl
                    else:
                        impl_int = namespace+'\\'+impl
                tmp_impls.append(impl_int)
            impl_dict[namespace+'\\'+tree.name] = tmp_impls

    # trait
    elif type(tree) == phpast.Trait:
        # 记录trait信息
        class_dict[namespace+'\\'+tree.name] = {'#type': 'trait'}
        # 补全use列表
        if not hasattr(tree, 'use_list'):
            tree.use_list = {}

        # 记录use trait关系，由于当前还没解析完所有代码，这里先粗略地记录use关系
        if tree.traits:
            use_trait_dict[namespace+'\\' +
                           tree.name] = [namespace, tree.use_list, tree.traits]

        add_trait_attr(tree, namespace, tree.use_list)

    # 单结点
    if hasattr(tree, 'node'):
        try:
            tree.node.parent = tree
        except AttributeError:
            pass
        tree_set_class_dict(tree.node, namespace, sourcefile)

    # params
    if hasattr(tree, 'params') and tree.params != None:
        for node in tree.params:
            try:
                node.parent = tree
            except AttributeError:
                pass
            tree_set_class_dict(node, namespace, sourcefile)

    # expr
    if hasattr(tree, 'expr'):
        try:
            tree.expr.parent = tree
        except AttributeError:
            pass
        tree_set_class_dict(tree.expr, namespace, sourcefile)

    # iftrue iffalse
    if hasattr(tree, 'iftrue'):
        try:
            tree.iftrue.parent = tree
            tree.iffalse.parent = tree
        except AttributeError:
            pass
        tree_set_class_dict(tree.iftrue, namespace, sourcefile)
        tree_set_class_dict(tree.iffalse, namespace, sourcefile)

    # 多结点
    if hasattr(tree, 'nodes'):
        for node in tree.nodes:
            try:
                node.parent = tree
            except AttributeError:
                pass
            tree_set_class_dict(node, namespace, sourcefile)

    # catch
    if hasattr(tree, 'catches'):
        for node in tree.catches:
            try:
                node.parent = tree
            except AttributeError:
                pass
            tree_set_class_dict(node, namespace, sourcefile)

    # IF
    if hasattr(tree, 'elseifs'):
        for node in tree.elseifs:
            node.parent = tree
            tree_set_class_dict(node, namespace, sourcefile)

    if hasattr(tree, 'else_'):
        try:
            tree.else_.parent = tree
        except AttributeError:
            pass
        tree_set_class_dict(tree.else_, namespace, sourcefile)

    if hasattr(tree, 'left'):
        try:
            tree.left.parent = tree
            tree.right.parent = tree
        except AttributeError:
            pass
        tree_set_class_dict(tree.left, namespace, sourcefile)
        tree_set_class_dict(tree.right, namespace, sourcefile)

    if hasattr(tree, 'key'):
        try:
            tree.value.parent = tree
        except AttributeError:
            pass
        tree_set_class_dict(tree.key, namespace, sourcefile)

    if hasattr(tree, 'value'):
        try:
            tree.value.parent = tree
        except AttributeError:
            pass
        tree_set_class_dict(tree.value, namespace, sourcefile)


def return_files(rootDir):
    list_dirs = os.walk(rootDir)
    funfiles = []
    for root, dirs, files in list_dirs:
        for f in files:
            funfiles.append(os.path.join(root, f))
    return funfiles


def load_cannot_user():
    '''
    统计wakeup中包含die或throw的无法反序列化的类
    '''
    global cannot_unser

    for vclass in class_dict:
        res = False
        if '__wakeup' in class_dict[vclass]:
            for tmp_node in class_dict[vclass]['__wakeup'].nodes:
                if type(tmp_node) in (phpast.Exit, phpast.Throw):
                    res = True
                    break
        if res:
            cannot_unser.add(vclass)


loaded = None  # 用于在处理继承和trait use时记录已加载过的类和trait


def dynamic_class_set_attr():
    '''
    解析目标目录下所有的php文件中的类，并记录类中的方法和属性

    不会去解析其中include的文件，每个文件只过一遍
    '''

    # 使用缓存
    if use_cache:
        try:
            # 使用update是为了保留原索引，python在引入库中的变量时会重新获取一个新变量，
            # 如果直接在这里赋值，在链查找时获得的是最初的那个索引（为空）
            # 不用管trait，因为trait的信息已经被解析到class_dict中了
            with open(attr_func_dict_cache, 'rb') as fr:
                attr_func_dict.update(pickle.load(fr))

            with open(class_dict_cache, 'rb') as fr:
                class_dict.update(pickle.load(fr))

            with open(global_func_dict_cache, 'rb') as fr:
                global_func_dict.update(pickle.load(fr))

            with open(cannot_unser_cache, 'rb') as fr:
                cannot_unser.update(pickle.load(fr))

            return
        except FileNotFoundError:
            # 创建、清空缓存文件夹
            try:
                shutil.rmtree(hunter_root+'/cache/')
            except FileNotFoundError:
                pass
            os.makedirs(hunter_root+'/cache/')

    files = return_files(php_prog_root)

    php_files = []

    # 获取php文件的绝对路径
    for i in range(len(files)):
        ext = files[i].split('.')[-1]
        if ext in php_exts:
            php_files.append(os.path.abspath(files[i]))
    del files

    # 解析php文件并加载类方法和类属性
    for vphpfile in php_files:
        if 'testcase' in vphpfile.lower():
            continue
        parser = make_parser()
        try:
            testphpfile = open(vphpfile, encoding='utf8').read()
        except UnicodeDecodeError:
            print('[warning] The file cannot be decoded: '+vphpfile)
            continue

        lexer.lexer.begin('INITIAL')
        lexer.lineno = 1

        try:
            vast = parser.parse(testphpfile, lexer=lexer)

        except SyntaxError as e:  # 语法错误时直接忽略掉该文件
            print(
                f'''[warning] SyntaxError in file "{vphpfile}", line {lexer.lineno}\n{e}''')
            continue

        os.chdir(os.path.dirname(vphpfile))  # 进入PHP的工作路径

        use_list = {}  # use语句的变量储存
        namespace = ''  # 初始化namespace

        for node in vast:

            # 设置顶层namespace
            if type(node) == phpast.Namespace and len(node.nodes) == 0:
                namespace = node.name

            # use语句记录
            elif type(node) == phpast.UseDeclarations:
                for tuse in node.nodes:
                    complete = tuse.name
                    if '\\' not in complete:  # 使用原生类
                        use_list[complete] = complete
                    else:
                        if tuse.alias != None:
                            tclassname = tuse.alias
                        else:
                            tclassname = complete.split('\\')[-1]
                        use_list[tclassname] = complete

            # use列表记录到node
            elif type(node) in (phpast.Class, phpast.Function, phpast.Trait, phpast.Interface):
                node.use_list = use_list

            # 记录全局函数
            tree_global_func_dict(node, namespace)

            # 设置class_dict
            tree_set_class_dict(node, namespace, vphpfile)

    global loaded
    # 根据use trait关系对trait属性和类属性进行添加
    loaded = set()
    for vclass in use_trait_dict:
        add_use_attr(vclass, set())

    # 根据接口关系解析接口属性
    loaded = set()
    for impl in impl_dict:
        add_impl_attr(impl, set())

    # 根据继承关系将父类方法和属性添加到子类
    loaded = set()
    for vclass in ext_dict:
        add_parent_attr(vclass, set())

    # 统计wakeup中包含die或throw的无法反序列化的类
    if exclude_die_wakeup:
        load_cannot_user()

    # 统计 方法名->类名 字典
    for vclass in class_dict:
        if '#type' in class_dict[vclass]:  # 不记录抽象类
            continue
        if vclass in cannot_unser:  # 不记录无法反序列化的类
            continue
        for attrname in class_dict[vclass]:
            # 特殊接口
            if attrname[0] == '!':
                try:  # 是否存在该键值
                    attr_func_dict[attrname]
                except KeyError:  # 不存在时创建键值
                    attr_func_dict[attrname] = []
                attr_func_dict[attrname].append(vclass)
                continue

            node = class_dict[vclass][attrname]
            # 成员方法，不记录抽象方法
            if type(node) == phpast.Method and 'abstract' not in node.modifiers:
                try:  # 是否存在该键值
                    attr_func_dict[node.name]
                except KeyError:  # 不存在时创建键值
                    attr_func_dict[node.name] = []
                attr_func_dict[node.name].append(vclass)

    if not os.path.exists(hunter_root+'/cache/'):
        os.makedirs(hunter_root+'/cache/')

    # 缓存代码信息
    with open(attr_func_dict_cache, 'wb') as fw:
        pickle.dump(attr_func_dict, fw)

    with open(class_dict_cache, 'wb') as fw:
        pickle.dump(class_dict, fw)

    with open(global_func_dict_cache, 'wb') as fw:
        pickle.dump(global_func_dict, fw)

    with open(cannot_unser_cache, 'wb') as fw:
        pickle.dump(cannot_unser, fw)


def add_parent_attr(vclass, extended: set):
    '''
    根据继承关系将class_dict中的父类方法和属性添加到子类
    需要从最里层开始解析（没有继承其他类的类）
    注意处理循环继承的情况
    '''

    if vclass in loaded:  # 一个类只加载一次
        return

    extended.add(vclass)  # extended记录的是当前类直接或间接继承过的类
    loaded.add(vclass)  # loaded记录的是**所有**解析过的类

    # 没有继承
    if vclass not in ext_dict:
        return
    else:
        ext_class = ext_dict[vclass]

        # # 跳过内置类
        # if ext_class in BuiltinClass:
        #     return

        if ext_class not in class_dict:
            if '\\' + ext_class in class_dict:  # 可能存在第一次解析时还未解析到的类
                ext_dict[vclass] = '\\' + ext_class
                ext_class = '\\' + ext_class
            else:
                print('[!] Error: Class not found:', ext_class)
                return

        # 先加载父类
        if ext_class not in extended:  # 防止循环继承，没继承过，才加载
            add_parent_attr(ext_class, extended)

        # 添加父类的属性
        for attrname in class_dict[ext_class]:
            # 不记录特殊信息
            if attrname[0] == '#':
                continue
            # 当前类已有的属性和方法不处理
            if attrname in class_dict[vclass]:
                continue

            attr = class_dict[ext_class][attrname]
            # 不记录抽象方法
            if type(attr) == phpast.Method and 'abstract' in attr.modifiers:
                continue

            class_dict[vclass][attrname] = attr


def add_impl_attr(impl, extended: set):
    '''
    根据接口关系解析class_dict中的接口属性
    '''

    if impl in loaded:  # 一个类只加载一次
        return

    extended.add(impl)
    loaded.add(impl)

    # 没有继承
    if impl not in impl_dict:
        return
    else:
        ext_impls = impl_dict[impl]
        for ext_impl in ext_impls:
            if ext_impl not in class_dict:
                if '\\' + ext_impl in class_dict:  # 可能存在第一次解析时还未解析到的接口
                    impl_dict[impl].remove(ext_impl)
                    impl_dict[impl].append('\\' + ext_impl)
                    ext_impl = '\\' + ext_impl
                else:
                    print('[!] Error: Interface not found:', ext_impl)
                    continue

            # 先加载父接口
            if ext_impl not in extended:  # 防止循环继承，没继承过，才加载
                add_impl_attr(ext_impl, extended)

            # 添加父接口的属性到本接口
            for attrname in class_dict[ext_impl]:
                # 不记录特殊信息
                if attrname[0] == '#':
                    continue
                class_dict[impl][attrname] = class_dict[ext_impl][attrname]


def add_use_attr(vclass, used: set):
    '''
    根据use trait关系将class_dict中的方法和属性添加到对应类中
    需要从最里层开始解析（没有use其他trait的trait）
    注意处理循环use的情况
    '''

    if vclass in loaded:  # 一个类只加载一次
        return

    used.add(vclass)  # used记录的是当前类/trait直接或间接use过的trait
    loaded.add(vclass)  # loaded记录的是**所有**解析过的trait

    # 没有use trait
    if vclass not in use_trait_dict:
        return
    else:
        namespace, tmp_uses, tmp_traits = use_trait_dict[vclass]

        for t_trait in tmp_traits:
            insteadof_d = {}
            as_d = {}

            for rename in t_trait.renames:
                if rename.insteadof != None:
                    insteadof_d[rename.vfrom.name] = rename.vfrom.node
                elif rename.vto != None:
                    as_d[rename.vto] = rename.vfrom

            # 还原完整trait名
            tmp_used = {}

            # 统一单trait和多trait
            if type(t_trait.name) == list:
                names = t_trait.name
            elif type(t_trait.name) == str:
                names = [t_trait.name]

            for tmp_name in names:
                # 绝对路径
                if tmp_name[0] == '\\':
                    tmp_used[tmp_name] = tmp_name
                # 相对路径
                else:
                    # 首先尝试是否是use语句的类
                    if tmp_name in tmp_uses:
                        tmp_used[tmp_name] = tmp_uses[tmp_name]
                    else:
                        tmp_used[tmp_name] = namespace+'\\'+tmp_name

            # 添加as属性
            for alias in as_d:
                # 只有一个trait时，属性用字符串表示
                if type(as_d[alias]) == str:
                    attrname = as_d[alias]
                    if attrname in class_dict[tmp_used[tmp_name]]:
                        attr = class_dict[tmp_used[tmp_name]
                                          ][attrname]  # tmp_name即当前用的trait
                    else:
                        print('[!] Error: Attribute not found:',
                              class_dict[tmp_used[tmp_name]], attrname)
                        continue
                # 多个trait时，属性需要指明具体的trait
                else:
                    attrname = as_d[alias].name
                    as_t = tmp_used[as_d[alias].node]
                    if as_t in class_dict:
                        if attrname in class_dict[as_t]:
                            attr = class_dict[as_t][attrname]
                        else:
                            print('[!] Error: Attribute not found:',
                                  class_dict[as_t], attrname)
                            continue
                    else:
                        print('[!] Error: Trait not found:', as_t)
                        continue

                class_dict[vclass][alias] = attr

            # 添加use trait属性
            for tkey in tmp_used:
                used_trait = tmp_used[tkey]
                # 先递归加载其use trait
                if used_trait not in used:  # 防止循环use，没use过才加载
                    add_use_attr(used_trait, used)

                if used_trait not in class_dict:
                    print('[!] Error: Trait not found:', used_trait)
                    continue

                # 添加use的属性
                for attrname in class_dict[used_trait]:
                    # 不记录特殊信息
                    if attrname[0] == '#':
                        continue
                    # 当前类已有的属性和方法不覆盖
                    if attrname in class_dict[vclass]:
                        continue
                    # instead语句
                    if attrname in insteadof_d:
                        insteadt = tmp_used[insteadof_d[attrname]]
                        if insteadt in class_dict:
                            attr = class_dict[insteadt][attrname]
                        else:
                            print('[!] Error: Trait not found:', insteadt)
                            continue
                        class_dict[vclass][attrname] = attr
                    # 一般情况
                    else:
                        attr = class_dict[used_trait][attrname]
                        class_dict[vclass][attrname] = attr


if __name__ == '__main__':
    pass
