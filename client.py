import requests as r
import time
from pprint import pprint
import json
data  = {
    'name': 'python-server3', 
    'image':    'python:3.10',
    'networks': ['bridge1'],
    'workingDir': '/app/garbage',
    'command': ['python', '-m', 'http.server', '8080'],
    'mounts':   {
        '/home/krishna/Projects/JAIL/garbage' : {
            'type':'bind',
            'source':'/app/garbage',
            'readonly':False
        }
    },
    "ports":[
        {
            "host":8080,
            "container":8080,
            "proto":"tcp"
        }
    ]
}




# start = time.time()*1000
# res = r.post('http://localhost:5000/api/containers', json=data)
# end = time.time()*1000
# print(res, end-start)
# data = res.json()
# data['status'] = {
#     'status':'created',
#     'PID':0,
#     'message': ''
# }
print(json.dumps(data, indent=4))