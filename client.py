import requests as r
import time
from pprint import pprint
import json
data  = {
    'name': 'redis-server', 
    'image':    'redis:8.2.3',
    'networks': ['bridge1']
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