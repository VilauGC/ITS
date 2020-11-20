from tinyec import (registry, ec)
import secrets
import pickle


def generateKeyPair_secp256r1():
    curve = registry.get_curve('secp256r1')
    r = secrets.randbelow(curve.field.n)
    V = r * curve.g
    return (r, V)


r, V = generateKeyPair_secp256r1()

# f = open("./secp256r1pubkeyITS.txt", 'wb')
# f.write(pickle.dumps(V))
# f.close()

# f = open("./secp256r1privkeyITS.txt", 'wb')
# f.write(pickle.dumps(r))
# f.close()
# f = open("../EA API/secp256r1pubkeyEA.txt", 'wb')
# f.write(pickle.dumps(V))
# f.close()

# f = open("../EA API/secp256r1privkeyEA.txt", 'wb')
# f.write(pickle.dumps(r))
# f.close()
f = open("C:\\1.workspace_vilau\\MASTER STI\\0.Disertatie\\ITS_PY\\AA_API\\secp256r1pubkeyAA.txt", 'wb')
f.write(pickle.dumps(V))
f.close()

f = open("C:\\1.workspace_vilau\\MASTER STI\\0.Disertatie\\ITS_PY\\AA_API\\secp256r1privkeyAA.txt", 'wb')
f.write(pickle.dumps(r))
f.close()
