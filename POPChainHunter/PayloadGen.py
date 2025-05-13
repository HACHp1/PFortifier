'''
Parse the controllable instance to PHP payload
'''

from POPChainHunter.utils import *
import json


class PayloadGen:

    all_class = None
    '''
    涉及到的类以及其用到的属性的字典

    self.all_class={
        'space1\\class1':set(attr1,attr2...),
        ...
    }
    '''

    pop_payload = '\n'  # pop链的payload，首先用换行隔开new和赋值语句

    def removeRef(self, ref, refkey):
        '''
        属性剪枝细节，根据ref删除对象，返回是否删除了对象
        '''
        if_remove = True

        # 去掉无类名的可控对象
        if type(ref[refkey]) == ControllableInstance and ref[refkey].classname == None:
            del ref[refkey]
        # 去掉不可控对象
        elif type(ref[refkey]) == PHPInstance:
            del ref[refkey]
        # 去掉空list、空dict
        elif type(ref[refkey]) == PHPArray:
            if len(ref[refkey]) == 0:
                del ref[refkey]
        # 去掉非source字符串
        elif type(ref[refkey]) == str and source_token not in ref[refkey]:
            del ref[refkey]
        # 去掉空值
        elif ref[refkey] == None:
            del ref[refkey]
        # 去掉基本类型
        elif type(ref[refkey]) in (int, float, bool):
            del ref[refkey]
        else:
            if_remove = False

        return if_remove

    def trimAttr(self, controllable):
        '''
        属性剪枝
        '''

        if type(controllable) == ControllableInstance:
            for attrname in list(controllable.attr.keys()):
                # 属性剪枝
                self.trimAttr(controllable.attr[attrname])  # 先处理叶子
                self.removeRef(controllable.attr, attrname)  # 再处理本节点

        elif type(controllable) == PHPArray:
            for key in list(controllable.keys()):
                # 属性剪枝
                self.trimAttr(controllable[key])  # 先处理叶子
                self.removeRef(controllable, key)  # 再处理本节点

        else:
            return

    def getAllClass(self, controllable):
        '''
        递归获得涉及到的类以及其用到的属性
        '''

        if type(controllable) == ControllableInstance or type(controllable) == PHPInstance:
            class_name = controllable.classname
            # 查看是否已记录该类
            try:
                self.all_class[class_name]
            except KeyError:
                self.all_class[class_name] = set()

            # 将属性添加进类中
            for attrname in controllable.attr:
                # if attrname == 'hasMore':
                #     print()
                self.all_class[class_name].add(attrname)
                # 进入下一层
                self.getAllClass(controllable.attr[attrname])

        elif type(controllable) == PHPArray:
            for key in controllable:
                # 进入下一层
                self.getAllClass(controllable[key])

        else:
            return

    def genPayload(self, controllable, cur_varname):
        '''
        根据字典生成payload

        输入：
        controllable: 可控对象
        cur_varname: 本实例的变量名，由上一层决定
        '''

        if type(controllable) == PHPArray:

            self.pop_payload = f'${cur_varname}=array();\n' + \
                self.pop_payload  # 对本数组进行初始化

            for key in controllable:  # 本数组中的每个key名

                # 生成并记录各属性的变量名 $xxx=xxx

                if type(controllable[key]) == PHPArray:
                    tmp_varname = 'array_'+random_string(6)

                elif type(controllable[key]) in (ControllableInstance, PHPInstance):
                    if controllable[key].classname == None:
                        continue
                    tmp_varname = controllable[key].classname.replace(
                        '\\', '_')+'_'+random_string(6)

                else:  # int、float等
                    tmp_varname = random_string(6)

                # 递归下一层
                self.genPayload(controllable[key], tmp_varname)

                # 将各属性变量赋值为本数组的键值
                self.pop_payload = self.pop_payload + \
                    f"${cur_varname}['{key}']=${tmp_varname};\n"

        # 对象
        elif type(controllable) in (ControllableInstance, PHPInstance):

            class_name = controllable.classname

            self.pop_payload = f'${cur_varname}=new {class_name}();\n' + \
                self.pop_payload  # 对本实例进行初始化

            for attrname in controllable.attr:  # 本类中的每个属性名

                # 生成并记录各属性的变量名 $xxx=xxx
                if type(controllable.attr[attrname]) == PHPArray:  # 如果下一个属性为对象或数组
                    tmp_varname = 'array_'+random_string(6)

                elif type(controllable.attr[attrname]) in (ControllableInstance, PHPInstance):
                    if controllable.attr[attrname].classname == None:
                        continue

                    tmp_varname = controllable.attr[attrname].classname.replace(
                        '\\', '_')+'_'+random_string(6)

                else:  # int、float等
                    tmp_varname = random_string(6)

                # 递归下一层
                self.genPayload(controllable.attr[attrname], tmp_varname)

                # 将各属性变量赋值为本实例的成员属性
                self.pop_payload = self.pop_payload + \
                    f'${cur_varname}->{attrname}=${tmp_varname};\n'

        # int、float等基本类型
        else:
            self.pop_payload = f'${cur_varname}={json.dumps(controllable)};\n' + \
                self.pop_payload

    def getPayload(self, controllable):
        '''
        输入对象字典，输出PHP payload
        '''

        self.all_class = {}  # 清空
        self.trimAttr(controllable)  # 属性剪枝
        self.getAllClass(controllable)

        pop_payload2 = ''

        # 类声明
        for vclass in self.all_class:

            if vclass == None:
                continue

            vclass_name = vclass.split('\\')[-1]
            vnamespace = vclass[:-(len(vclass_name)+1)]

            tmp = ''
            for attr in list(self.all_class[vclass]):
                tmp = tmp+'public $'+attr+';\n'
            pop_payload2 = pop_payload2 + \
                f'namespace {vnamespace}{{\nclass {vclass_name}{{\n{tmp}}}\n}}\n'

        # 类属性赋值
        if hasattr(controllable, 'classname'):
            tmp_varnmae = controllable.classname.replace(
                '\\', '_')+'_'+random_string(6)
        elif type(controllable) == PHPArray:
            tmp_varnmae = 'array_'+random_string(6)
        else:
            tmp_varnmae = random_string(6)

        self.genPayload(controllable, tmp_varnmae)

        # 获取反序列化payload
        pop_payload_r = '<?php\n'+pop_payload2 + \
            'namespace{\n'+self.pop_payload+'\n' + \
            f'echo urlencode(serialize(${tmp_varnmae}));'+'\n}'

        self.pop_payload = '\n'  # 初始化payload

        return pop_payload_r


if __name__ == '__main__':
    a = ControllableInstance('Space1\\Main')
    a.attr['ClassObj'] = ControllableInstance('Space1\\Main')
    a.attr['ClassObj'].attr['a'] = ControllableInstance('Space1\\Test1')
    a.attr['ClassObj'].attr['b'] = PHPArray({
        "test": ControllableInstance('Space1\\Test2')
    })

    payloadGen = PayloadGen()

    print(payloadGen.getPayload(a))
