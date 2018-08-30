import requests

print("calling API")
#res=requests.get('http://45.62.252.151:8080/api/search/cmp/car')
res=requests.get('http://45.62.252.151:8080/api/search/slack/all/delhi')
#res=requests.get('http://45.62.252.151:8080/api/search/slack/all/ford,jeep,2016')
print(res.json())
