'''
graph generate
'''

from py2neo import Graph, Node, Relationship


class MethodNode:
    '''
    方法节点
    '''
    signature = ''  # 类名+"#"+方法名（类方法签名）
    className = ''  # 所在类的完整类名
    methodName = ''  # 方法名
    isSink = False  # 是否为污点方法
    sinkLines = None  # 记录污点行数
    sourceFile = ''  # 所在源文件名
    lineNo = None  # 所在行数

    def __init__(self, className, methodName, sourceFile, lineNo):
        self.signature = className+'#'+methodName
        self.className = className
        self.methodName = methodName
        self.sourceFile = sourceFile
        self.lineNo = lineNo
        self.sinkLines = set()


class MethodCallEdge:
    '''
    方法调用边
    '''
    signature = ''  # 类名1+"#"+方法名1"->"+类名2+"#"+方法名2（调用签名）
    callerClass = ''  # 当前方法的类名
    callerMtd = ''  # 当前方法名
    calleeClass = ''  # 调用对象类名
    calleeMtd = ''  # 调用方法名
    sourceFile = ''  # 所在源文件名
    lineNo = None  # 所在行数

    def __init__(self, callerClass, callerMtd, calleeClass, calleeMtd, sourceFile, lineNo):
        self.signature = callerClass+"#"+callerMtd+"->"+calleeClass+"#"+calleeMtd
        self.sourceFile = sourceFile
        self.lineNo = lineNo
        self.callerClass = callerClass
        self.callerMtd = callerMtd
        self.calleeClass = calleeClass
        self.calleeMtd
        self.sourceFile = sourceFile
        self.lineNo = lineNo


class GraphCollector:
    '''
    图信息收集器，主要是收集调用图信息

    Method（类方法）

    - Signature：类名+"#"+方法名（类方法签名）
    - ClassName：所在类的完整类名
    - MethodName：方法名
    - IsSink：是否为污点方法
    - SinkLines：污点的行数
    - SourceFile：所在源文件名
    - LineNo：所在行数

    MethodCall（调用边）

    - Signature：类名1+"#"+方法名1"->"+类名2+"#"+方法名2（调用签名）
    - CurClass：当前方法的类名
    - CurMethod：当前方法名
    - Receiver：调用对象类名
    - CalledMethod：调用方法名
    - SourceFile：所在源文件名
    - LineNo：所在行数
    '''

    graphdb = None

    '''
    { 类名+"#"+方法名 : MethodNode }
    '''
    nodes = None

    '''
    { 类名1+"#"+方法名1"->"+类名2+"#"+方法名2 : MethodCallNode }
    '''
    edges = None

    def __init__(self, password):
        self.graphdb = Graph('http://localhost:7474', password=password)
        self.nodes = {}
        self.edges = {}

    def saveMethodCall(self, callerClass, callerMtd, calleeClass, calleeMtd, callerFile, callerLineNo, calleeFile, calleeLineNo):
        '''
        将调用图的节点和边储存到字典
        去重、对sink方法进行贪婪法标记
        '''

        # 储存方法节点
        self.saveMethod(callerClass, callerMtd, None, None)
        self.saveMethod(calleeClass, calleeMtd, calleeFile, calleeLineNo)

        # 储存调用边
        self.saveCallsite(callerClass, callerMtd, calleeClass,
                          calleeMtd, callerFile, callerLineNo)

    def saveMethod(self, classname, method, srcfile, lineno):
        '''
        仅储存方法
        '''
        methodSig = classname + '#' + method
        if methodSig not in self.nodes:
            self.nodes[methodSig] = MethodNode(
                classname, method, srcfile, lineno
            )

    def saveCallsite(self, callerClass, callerMtd, calleeClass, calleeMtd, csFile, csLineno):
        '''
        仅储存调用点
        '''
        callSig = callerClass+"#"+callerMtd+"->"+calleeClass+"#"+calleeMtd
        if callSig not in self.edges:
            self.edges[callSig] = MethodCallEdge(
                callerClass, callerMtd, calleeClass, calleeMtd, csFile, csLineno
            )

    def setSinkMethod(self, methodSig, lineno):
        '''
        设置方法的sink属性
        '''
        if methodSig in self.nodes:
            self.nodes[methodSig].isSink = True
            self.nodes[methodSig].sinkLines.add(lineno)

    def save2neo4j(self):
        '''
        将收集结果储存到neo4j
        '''

        # 储存节点
        neo4jNodes = {}
        for tmpSig in self.nodes.keys():
            neo4jNodes[tmpSig] = Node(
                'Method',
                Signature=self.nodes[tmpSig].signature,
                ClassName=self.nodes[tmpSig].className,
                MethodName=self.nodes[tmpSig].methodName,
                IsSink=self.nodes[tmpSig].isSink,
                SinkLines=list(self.nodes[tmpSig].sinkLines),
                SourceFile=self.nodes[tmpSig].sourceFile,
                LineNo=self.nodes[tmpSig].lineNo,
            )

            self.graphdb.create(neo4jNodes[tmpSig])

        # 储存边
        for tmpSig in self.edges.keys():
            caller, callee = tmpSig.split('->')
            relation = Relationship(
                neo4jNodes[caller],
                'MethodCall',
                neo4jNodes[callee],
                Signature=tmpSig,
                CurClass=self.edges[tmpSig].callerClass,
                CurMethod=self.edges[tmpSig].callerMtd,
                Receiver=self.edges[tmpSig].calleeClass,
                CalledMethod=self.edges[tmpSig].calleeMtd,
                SourceFile=self.edges[tmpSig].sourceFile,
                LineNo=self.edges[tmpSig].lineNo,
            )

            self.graphdb.create(relation)
