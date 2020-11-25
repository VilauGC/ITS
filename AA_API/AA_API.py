import sys
sys.path.append("C:\\1.workspace_vilau\\MASTER STI\\0.Disertatie\\ITS_PY\\UTILS")

from flask import Flask, request

app = Flask(__name__)

@app.route('/its-authorization', methods=['POST'])
def its_authorization():
    req_json = request.get_json()
    print(req_json)
    return {'hello': 1}


app.run(port=5002)