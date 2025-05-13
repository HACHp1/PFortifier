from POPChainHunter.PayloadGen import PayloadGen
from POPChainHunter.utils import *

if __name__ == '__main__':
    a = ControllableInstance('Space1\\Main')
    a.attr['ClassObj'] = ControllableInstance('Space1\\Main')
    a.attr['ClassObj'].attr['a'] = ControllableInstance('Space1\\Test1')
    a.attr['ClassObj'].attr['b'] = PHPArray({
        "test": ControllableInstance('Space1\\Test2')
    })

    payloadGen = PayloadGen()

    print(payloadGen.getPayload(a))