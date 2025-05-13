# 记录所有出现的内置接口，注意不包括内置类

BuiltinInterface = {
    '\\Iterator': {
        '#type': 'interface',
        '!iterator': 1,
    },
    '\\IteratorAggregate': {
        '#type': 'interface',
        '!iteratoraggregate': 1,
    },
    '\\ArrayAccess': {
        '#type': 'interface',
        '!arrayaccess': 1,
    },
    '\\ArrayObject': {
        '#type': 'interface',
    },
    "\\SeekableIterator": {
        '#type': 'interface',
    },
    "\\RecursiveIterator": {
        '#type': 'interface',
    },
}

# 记录内置的类或接口，实现或继承接口的关系，即 XXX->接口；注意key包括内置类，value则全是内置接口

BuiltinIntExtends = {
    '\\ArrayObject': ['\\IteratorAggregate', '\\ArrayAccess', ],
    '\\SeekableIterator': ['\\Iterator'],
    '\\ArrayIterator': ['\\SeekableIterator', '\\ArrayAccess', ],
    "\\RecursiveIterator": ['\\Iterator'],
    "\\RecursiveArrayIterator": ["\\RecursiveIterator"],
}
