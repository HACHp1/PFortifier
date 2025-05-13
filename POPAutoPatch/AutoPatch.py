'''
patch generation
'''

from POPChainHunter.utils import *


class AutoPatch:

    replace = None  # 用于替换时使用

    def ast2phpcode(self, vast):
        '''
        递归地将属性ast转化为PHP代码，用于patch时确定被判断的实体

        目标：
        $xxx;
        $this->ClassObj['12'];
        $this->ClassObj->a;
        $this->method();
        '''

        if type(vast) == str:
            return vast
        elif type(vast) == int:
            return str(vast)
        elif type(vast) == phpast.Variable:
            return vast.name
        elif type(vast) == phpast.ArrayOffset:
            if type(vast.expr) == str:
                offset = f'\'{vast.expr}\''
            else:
                offset = self.ast2phpcode(vast.expr)
            return f'{self.ast2phpcode(vast.node)}[{offset}]'
        elif type(vast) == phpast.ObjectProperty:
            return f'{self.ast2phpcode(vast.node)}->{self.ast2phpcode(vast.name)}'
        elif type(vast) == phpast.MethodCall:
            par_li = []
            for par in vast.params:
                par_li.append(self.ast2phpcode(par.node))
            par_li = ','.join(par_li)
            method_call = f'{self.ast2phpcode(vast.node)}->{self.ast2phpcode(vast.name)}({par_li})'
            replaced = '$' + method_call.replace(
                '->', '_').replace('(', '_').replace(')', '_').replace(',', '_').replace(' ', '_').replace('$', '')
            self.replace.append([method_call, replaced])
            return replaced
        else:
            print('[!] Error: cannot handle the AST:', vast)

    def get_patch(self, jmpNodeList):
        '''
        根据pop链获取patch

        input: jmpNodeList
        return: [patch, sourcefile, lineno]
        '''

        res = None
        self.replace = []

        # 对跳转节点按顺序修复，直到出现修复为止
        for jmpNode in jmpNodeList:

            # __call
            # this->xxx->xxx()
            if type(jmpNode) == CallNode:
                inst = self.ast2phpcode(jmpNode.node.node)
                if inst != None:
                    res = [
                        f'if(!method_exists({inst},\'{jmpNode.name}\')){{die();}}', jmpNode.sourcefile, jmpNode.lineno]

            # __get
            # this->xxx->xxx
            elif type(jmpNode) == phpast.ObjectProperty:
                inst = self.ast2phpcode(jmpNode.node)
                if inst != None:
                    res = [
                        f'if(!property_exists({inst},\'{jmpNode.name}\')){{die();}}', jmpNode.sourcefile, jmpNode.lineno]

            # __set
            # this->xxx->xxx=xxx
            elif type(jmpNode) == phpast.Assignment:
                inst = self.ast2phpcode(jmpNode.node.node)
                if inst != None:
                    res = [
                        f'if(!property_exists({inst},\'{jmpNode.node.name}\')){{die();}}', jmpNode.sourcefile, jmpNode.lineno]

            # __isset
            # isset(this->xxx->xxx)
            elif type(jmpNode) == phpast.IsSet:
                inst = self.ast2phpcode(jmpNode.nodes[0].node)
                if inst != None:
                    res = [
                        f'if(!property_exists({inst},\'{jmpNode.nodes[0].name}\')){{die();}}', jmpNode.sourcefile, jmpNode.lineno]

            # __unset
            # unset(this->xxx->xxx)
            elif type(jmpNode) == phpast.Unset:
                inst = self.ast2phpcode(jmpNode.nodes[0].node)
                if inst != None:
                    res = [
                        f'if(!property_exists({inst},\'{jmpNode.nodes[0].name}\')){{die();}}', jmpNode.sourcefile, jmpNode.lineno]

            # __toString
            elif type(jmpNode) == ToStringNode:
                inst = self.ast2phpcode(jmpNode.node)
                if inst != None:
                    res = [f'if(!is_string({inst})){{die();}}',
                           jmpNode.sourcefile, jmpNode.lineno]

            # iterator
            elif type(jmpNode) == IteratorNode:
                inst = self.ast2phpcode(jmpNode.node)
                if inst != None:
                    res = [f'if({inst} instanceof Iterator){{die();}}',
                           jmpNode.sourcefile, jmpNode.lineno]

            # arrayaccess
            elif type(jmpNode) == ArrayAccessNode:
                inst = self.ast2phpcode(jmpNode.node)
                if inst != None:
                    res = [f'if({inst} instanceof ArrayAccess){{die();}}',
                           jmpNode.sourcefile, jmpNode.lineno]

            if res != None:
                return [res, self.replace]

        return res
