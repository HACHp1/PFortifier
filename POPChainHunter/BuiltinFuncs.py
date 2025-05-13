# coding=utf-8


'''
php内置函数模拟

传入：par_li
传出：该函数真实的模拟值

内置函数中可能会涉及到内置类的操作，所以需要引入内置类
'''

import base64
import os
from urllib.parse import unquote, quote
from POPChainHunter.utils import ControllableInstance, PHPInstance, source_token, attr_func_dict, PHPArray
from phply import phpast

'''
常量记录表
'''

const_vars = {}


# def php_define(astexec, par_li, node):
#     '''
#     常量定义函数
#     '''
#     if len(par_li) > 1:
#         global const_vars
#         const_vars[get_thr_id()][par_li[0]] = par_li[1]


# def php_getallheaders(astexec, par_li, node):
#     return AutoFitDict()  # 可以返回任意键对应的值


def php_md5(astexec, par_li, node):  # md5过的字符串可以不用关心
    return 'DONTCARE'


def php_serialize(astexec, par_li, node):
    '''
    对于source，反序列化函数的作用类似于添加转义
    '''
    ret_val = ''
    if len(par_li) > 0 and type(par_li[0]) == str and 'SOURCE_TOKEN' in par_li[0]:
        ret_val = par_li[0].replace('"', '\\"').replace('\'', '\\\'')

    return ret_val


def php_addslashes(astexec, par_li, node):
    ret_val = ''

    if len(par_li) > 0 and par_li[0] != None:
        if type(par_li[0]) == ControllableInstance:
            ret_val = astexec.controllable_assign(par_li[0], source_token)
        else:
            ret_val = par_li[0].replace('"', '\\"').replace('\'', '\\\'')

    return ret_val


def php_stripslashes(astexec, par_li, node):
    ret_val = ''

    if len(par_li) > 0 and par_li[0] != None:
        ret_val = par_li[0].replace('\\', '')

    return ret_val


def php_stripcslashes(astexec, par_li, node):
    return par_li[0]


def php_addcslashes(astexec, par_li, node):
    return par_li[0]


def php_mysql_escape_string(astexec, par_li, node):
    return php_addslashes(par_li)


def php_mysql_real_escape_string(astexec, par_li, node):
    return php_addslashes(par_li)


def php_htmlspecialchars(astexec, par_li, node):

    ret_val = ''
    par_li[0] = astexec.tostr(par_li[0], node.params[0].node)
    # xss去污
    if len(par_li) > 0 and par_li[0] != None and 'SOURCE_TOKEN' in par_li[0]:
        ret_val = par_li[0].replace('<', '&lt;').replace('>', '&gt;')

    return ret_val


def php_htmlentities(astexec, par_li, node):

    ret_val = ''
    par_li[0] = astexec.tostr(par_li[0], node.params[0].node)
    # xss去污
    if len(par_li) > 0 and par_li[0] != None and 'SOURCE_TOKEN' in par_li[0]:
        ret_val = par_li[0].replace('<', '&lt;').replace('>', '&gt;')

    return ret_val


def php_base64_decode(astexec, par_li, node):

    par_li[0] = astexec.tostr(par_li[0], node.params[0].node)
    if len(par_li) > 0 and par_li[0] != None and 'SOURCE_TOKEN' in par_li[0]:
        ret_val = par_li[0]
    else:
        ret_val = base64.b64decode(par_li[0])

    return ret_val


def php_strlen(astexec, par_li, node):
    par_li[0] = astexec.tostr(par_li[0], node.params[0].node)
    if type(par_li[0]) == str:
        return len(par_li[0])
    else:
        return None


def php_strtolower(astexec, par_li, node):
    par_li[0] = astexec.tostr(par_li[0], node.params[0].node)
    if len(par_li) > 0 and par_li[0] != None and 'SOURCE_TOKEN' in par_li[0]:
        ret_val = par_li[0]
    elif par_li[0] == None:
        ret_val = 'DONTCARE'
    else:
        ret_val = par_li[0].lower()

    return ret_val


def php_substr(astexec, par_li, node):
    par_li[0] = astexec.tostr(par_li[0], node.params[0].node)
    ret_val = 'DONTCARE'

    try:
        if len(par_li) > 0 and par_li[0] != None and 'SOURCE_TOKEN' in par_li[0]:
            ret_val = par_li[0]
        elif len(par_li) == 2:
            ret_val = par_li[0][par_li[1]:]
        elif len(par_li) == 3:
            ret_val = par_li[0][par_li[1]:par_li[1]+par_li[2]]
    except Exception:
        pass

    return ret_val


def php_strrchr(astexec, par_li, node):

    if len(par_li) > 0 and par_li[0] != None and 'SOURCE_TOKEN' in par_li[0]:
        ret_val = par_li[0]
    else:
        ret_val = par_li[0].split(par_li[1])[-1]

    return ret_val


def php_strpos(astexec, par_li, node):
    if type(par_li[0]) != ControllableInstance:
        par_li[0] = astexec.tostr(par_li[0], node.params[0].node)
        par_li[1] = astexec.tostr(par_li[1], node.params[1].node)
        return par_li[0].find(par_li[1])


def php_stristr(astexec, par_li, node):
    pos = par_li[0].upper().find(par_li[1].upper())
    return par_li[0][pos:]


def php_preg_replace(astexec, par_li, node):
    # 目前只处理str类型
    par_li[0] = astexec.tostr(par_li[0], node.params[0].node)
    par_li[1] = astexec.tostr(par_li[1], node.params[1].node)
    par_li[2] = astexec.tostr(par_li[2], node.params[2].node)

    if len(par_li) > 2 and par_li[2] != None and 'SOURCE_TOKEN' in par_li[2]:
        ret_val = par_li[2]
    else:
        ret_val = 'DONTCARE'

    return ret_val


def php_strstr(astexec, par_li, node):
    pos = par_li[0].find(par_li[1])
    return par_li[0][pos:]


def php_str_replace(astexec, par_li, node):  # 这中间会存在一些去污的情况，需要在实际情况下慢慢积累
    if None in par_li:
        return

    par_li[1] = astexec.tostr(par_li[1], node.params[1].node)
    res = astexec.tostr(par_li[2], node.params[2].node)

    if source_token in res:
        return res

    if type(par_li[0]) == PHPArray:
        for find in par_li[0]:
            res = res.replace(par_li[0][find], par_li[1])
    else:
        res = res.replace(par_li[0], par_li[1])

    return res


def php_str_ireplace(astexec, par_li, node):
    if None in par_li:
        return
    for i in range(3):
        par_li[i] = par_li[i].upper()
    return par_li[2].replace(par_li[0], par_li[1])


def php_iconv(astexec, par_li, node):
    return par_li[2]


def php_curl_init(astexec, par_li, node):
    curlHandle = PHPInstance('curlhandle')
    if len(par_li) > 0:  # 第一个参数为url
        curlHandle.attr['url'] = par_li[0]
    return curlHandle


def php_curl_setopt(astexec, par_li, node):
    if par_li[1] == 'CURLOPT_URL':
        par_li[0].attr['url'] = par_li[2]


def php_urldecode(astexec, par_li, node):
    if par_li[0] != None:
        return unquote(par_li[0])


def php_urlencode(astexec, par_li, node):
    if par_li[0] != None:
        return quote(par_li[0])


def php_trim(astexec, par_li, node):
    if par_li[0] != None:
        par_li[0] = astexec.tostr(par_li[0], node.params[0].node)
        if len(par_li) == 1:
            return par_li[0].strip()
        else:
            return par_li[0].strip(par_li[0])


def php_rtrim(astexec, par_li, node):
    if par_li[0] != None:
        par_li[0] = astexec.tostr(par_li[0], node.params[0].node)
        if len(par_li) == 1:
            return par_li[0].rstrip()
        else:
            return par_li[0].rstrip(par_li[1])


def php_ltrim(astexec, par_li, node):
    if par_li[0] != None:
        par_li[0] = astexec.tostr(par_li[0], node.params[0].node)
        if len(par_li) == 1:
            return par_li[0].lstrip()
        else:
            return par_li[0].lstrip(par_li[1])


def php_count(astexec, par_li, node):
    if type(par_li[0]) == ControllableInstance and par_li[0].classname == None:
        ret = astexec.controllable_assign(par_li[0], [0])
        return ret
    elif type(par_li[0]) != PHPArray:
        return 'DONTCARE'

    return len(par_li[0])


def php_reset(astexec, par_li, node):
    try:
        return par_li[0][0]
    except Exception:
        return None


def php_end(astexec, par_li, node):
    if type(par_li[0]) == ControllableInstance:
        par_li[0] = astexec.controllable_arr_assign(par_li[0], source_token)
    if len(par_li[0]) > 0:
        return par_li[0][-1]


def php_explode(astexec, par_li, node):
    if type(par_li[1]) != ControllableInstance:
        par_li[0] = astexec.tostr(par_li[0], node.params[0].node)
        par_li[1] = astexec.tostr(par_li[1], node.params[1].node)
        return par_li[1].split(par_li[0])


def php_implode(astexec, par_li, node):

    try:
        if par_li[1] == None:
            return par_li[0]
        if type(par_li[1]) == ControllableInstance and par_li[1].classname == None:
            return source_token
        elif type(par_li[1]) == PHPArray:
            return par_li[0].join(par_li[1].items())
    except Exception:
        return None


def php_fopen(astexec, par_li, node):
    resource = PHPInstance('resource')

    if len(par_li) > 0:  # 第一个参数为url
        resource.attr['filename'] = par_li[0]

    return resource


def php_pathinfo(astexec, par_li, node):

    res = {}

    par_li[0] = astexec.tostr(par_li[0], node.params[0].node)

    if len(par_li) > 1:  # 有两个参数时，只取字典中的一个值
        res = par_li[0]
    elif 'SOURCE_TOKEN' in par_li[0]:
        # res = {
        #     'dirname': get_polypayload()[0],
        #     'basename': get_polypayload()[0],
        #     'extension': get_polypayload()[0],
        #     'filename': get_polypayload()[0],
        # }

        res = {
            'dirname': par_li[0],
            'basename': par_li[0],
            'extension': par_li[0],
            'filename': par_li[0],
        }

    return res


def php_dirname(astexec, par_li, node):
    res = 'DONTCARE'
    if par_li[0] == None:
        return res
    if 'SOURCE_TOKEN' in par_li[0]:
        res = par_li[0]
    else:
        res = os.path.dirname(par_li[0])
    return res


def php_array_unshift(astexec, par_li, node):
    '''
    array_unshift的操作比较奇葩，会把原来的字典数字key全部重置，但字符串key保留
    '''
    if type(par_li[0]) == PHPArray:
        for ele in par_li[-1:0:-1]:
            par_li[0].insertFirst(ele)

    return None


def php_array_map(astexec, par_li, node):

    ret_val = None
    if type(par_li[0]) == phpast.Closure:
        if type(par_li[1]) == ControllableInstance and par_li[1].classname == None:
            par_li[1] = astexec.controllable_assign(par_li[1], 0)
            ret_val = astexec.call_closure(par_li[0], par_li[1], node)

    return ret_val


def php_file_exists(astexec, par_li, node):
    par_li[0] = astexec.tostr(par_li[0], node.params[0].node)


def php_property_exists(astexec, par_li, node):
    '''
    用property_exists判断过的对象被强制赋予source_token类
    '''
    if type(par_li[0]) == ControllableInstance:
        par_li[0].classname = source_token
        # astexec.controllable_assign(par_li[0], 'DONTCARE')


def php_method_exists(astexec, par_li, node):
    '''
    用method_exists判断过的对象被强制赋予source_token类
    '''
    if type(par_li[0]) == ControllableInstance:
        try:
            if type(node.parent.parent.node.nodes[0]) == phpast.Exit:
                par_li[0].classname = source_token
        except AttributeError:
            pass


def php_is_string(astexec, par_li, node):
    if type(par_li[0]) == ControllableInstance:
        if type(node.parent) == phpast.If:
            astexec.controllable_assign(par_li[0], source_token)


def php_sprintf(astexec, par_li, node):
    return astexec.tostr(par_li[1], node.params[1].node)


def php_preg_match(astexec, par_li, node):
    par_li[0] = astexec.tostr(par_li[0], node.params[0].node)
    par_li[1] = astexec.tostr(par_li[1], node.params[1].node)
    return 'DONTCARE'


def php_array_merge(astexec, par_li, node):
    '''
    这里用了偷懒的做法：原php采用拷贝merge，这里直接在原array上进行update操作
    '''

    if type(par_li[0]) == ControllableInstance:
        par_li[0] = astexec.controllable_arr_assign(par_li[0], source_token)
    if type(par_li[1]) == ControllableInstance:
        par_li[1] = astexec.controllable_arr_assign(par_li[1], source_token)

    if type(par_li[0]) == PHPArray and type(par_li[1]) == PHPArray:
        par_li[0].update(par_li[1])
        return par_li[0]
    else:
        return 'DONTCARE'


def php_next(astexec, par_li, node):
    if type(par_li[0]) == ControllableInstance:
        par_li[0] = astexec.controllable_arr_assign(par_li[0], 0)
        return par_li[0][0]
    else:
        return 'DONTCARE'


def php_func_get_args(astexec, par_li, node):
    return par_li


def php_var_export(astexec, par_li, node):
    if len(par_li) >= 2:
        return par_li[0]
    else:
        return 'DONTCARE'


def php_glob(astexec, par_li, node):
    par_li[0] = astexec.tostr(par_li[0], node.params[0].node)
    if source_token in par_li[0]:
        tmp_arr = PHPArray()
        tmp_arr[0] = source_token
        return tmp_arr


def php_array_slice(astexec, par_li, node):
    return par_li[0]


def php_json_encode(astexec, par_li, node):
    if hasattr(par_li[0], 'isControllable') and par_li[0].isControllable:
        return source_token
    if type(par_li[0]) == PHPArray:
        for key in par_li[0]:
            if hasattr(par_li[0][key], 'isControllable') and par_li[0][key].isControllable:
                return source_token


def php_array_values(astexec, par_li, node):
    if hasattr(par_li[0], 'isControllable'):
        return par_li[0]


def php_is_resource(astexec, par_li, node):
    if hasattr(par_li[0], 'isControllable'):
        return False


def php_date(astexec, par_li, node):
    ret_val = astexec.tostr(par_li[0], node.params[0].node)
    return ret_val


builtin_func = {
    # 'define': php_define,
    # 'getallheaders': php_getallheaders,
    'md5': php_md5,
    'serialize': php_serialize,
    'htmlspecialchars': php_htmlspecialchars,
    'base64_decode': php_base64_decode,
    'strlen': php_strlen,
    'str_replace': php_str_replace,
    'str_ireplace': php_str_ireplace,
    'strrchr': php_strrchr,
    'substr': php_substr,
    'htmlentities': php_htmlentities,
    'addslashes': php_addslashes,
    'mysql_escape_string': php_mysql_escape_string,
    'mysql_real_escape_string': php_mysql_real_escape_string,
    'curl_init': php_curl_init,
    'curl_setopt': php_curl_setopt,
    'urldecode': php_urldecode,
    'rawurldecode': php_urldecode,
    'urlencode': php_urlencode,
    'rawurlencode': php_urlencode,
    'trim': php_trim,
    'php_ltrim': php_ltrim,
    'php_rtrim': php_rtrim,
    'count': php_count,
    'reset': php_reset,
    'end': php_end,
    'strtolower': php_strtolower,
    'explode': php_explode,
    'stripslashes': php_stripslashes,
    'implode': php_implode,
    'join': php_implode,
    'strpos': php_strpos,
    'stristr': php_stristr,
    'preg_replace': php_preg_replace,
    'strstr': php_strstr,
    'strchr': php_strstr,
    'iconv': php_iconv,
    'fopen': php_fopen,
    'stripcslashes': php_stripcslashes,
    'addcslashes': php_addcslashes,
    'pathinfo': php_pathinfo,
    'dirname': php_dirname,
    'array_unshift': php_array_unshift,
    'array_map': php_array_map,
    'file_exists': php_file_exists,
    'property_exists': php_property_exists,
    'method_exists': php_method_exists,
    'is_string': php_is_string,
    'sprintf': php_sprintf,
    'preg_match': php_preg_match,
    'array_merge': php_array_merge,
    'next': php_next,
    'func_get_args': php_func_get_args,
    "var_export": php_var_export,
    'glob': php_glob,
    'array_slice': php_array_slice,
    'json_encode': php_json_encode,
    'array_values': php_array_values,
    'is_resource': php_is_resource,
    'date': php_date,
}
