#!/usr/bin/env python

import os, random, requests
from flask import Flask, abort, request, jsonify, g, url_for, Response
#from flask_sqlalchemy import SQLAlchemy
from flask_httpauth import HTTPBasicAuth
from passlib.apps import custom_app_context as pwd_context
from itsdangerous import (TimedJSONWebSignatureSerializer as Serializer, BadSignature, SignatureExpired)
from datetime import datetime
from elasticsearch import Elasticsearch
import json

# initialization

app = Flask(__name__)
app.config['SECRET_KEY'] = 'colleague marketplace hash'
#app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True
# extensions
#db = SQLAlchemy(app)
auth = HTTPBasicAuth()
es=Elasticsearch()
#g.auth=auth

#class User(db.Model):
#    __tablename__ = 'users'
#    id = db.Column(db.Integer, primary_key=True)
#    username = db.Column(db.String(32), index=True)
#    password_hash = db.Column(db.String(64))
#    def hash_password(self, password):
#        self.password_hash = pwd_context.encrypt(password)
#    def verify_password(self, password):
#        return pwd_context.verify(password, self.password_hash)
#    def generate_auth_token(self, expiration):
#        s = Serializer(app.config['SECRET_KEY'], expires_in=expiration)
#        return s.dumps({'id': self.id})

#    @staticmethod
#    def verify_auth_token(token):
#        s = Serializer(app.config['SECRET_KEY'])
#        try:
#            data = s.loads(token)
#        except SignatureExpired:
#            return None    # valid token, but expired
#        except BadSignature:
#            return None    # invalid token
#       user = User.query.get(data['id'])
#        return user



@auth.verify_password
def verify_password(username_or_token, password):
    # first try to authenticate by token
    user = User.verify_auth_token(username_or_token)
    if not user:
        # try to authenticate with username/password
        user = User.query.filter_by(username=username_or_token).first()
        if not user or not user.verify_password(password):
            return False
    g.user = user
    return True

@app.route('/api/users', methods=['POST'])
def new_user():
    print("Hello")
    print(request.get_data())
    try:
        print(request.json['username'])
    except:
        print("Json parse error")
        abort(400)

    username = request.json.get('username')
    password = request.json.get('password')
    print("{},{}".format(username,password))
    #User=authorize.User
    if username is None or password is None:
        abort(400)    # missing arguments
    if User.query.filter_by(username=username).first() is not None:
        abort(400)    # existing user
    user = User(username=username)
    user.hash_password(password)
    db.session.add(user)
    db.session.commit()
    return (jsonify({'username': user.username}), 201,
            {'Location': url_for('get_user', id=user.id, _external=True)})


@app.route('/api/users/<int:id>')
def get_user(id):
    #user = authorize.User.query.get(id)
    user=User.query.get(id)
    if not user:
        abort(400)
    return jsonify({'username': user.username})

###Validate token
###
@app.route('/api/token')
@auth.login_required
def get_auth_token():
    token = g.user.generate_auth_token()
    return jsonify({'token': token.decode('ascii'), 'duration': 3600})

@app.route('/api/resource')
@auth.login_required
def get_resource():
    return jsonify({'data': 'Hello, %s!' % g.user.username})


@app.route('/api/search/<indexS>/<searchstring>')
def getDocuments(indexS,searchstring):
    res = es.search(index=indexS, body={"query": {"match": {"tags": searchstring}}})
    docList=[]
    print("Got %d Hits:" % res['hits']['total'])
    for hit in res['hits']['hits']:
        print("%(timestamp)s %(author)s: %(text)s" % hit["_source"])
        #docList.append(json.dumps(hit["_source"]))
        docList.append(hit["_source"])
    jsondumpstr= json.dumps(docList)
    return jsonify({'matchingdocs':jsondumpstr})

@app.route('/api/add',methods=['POST'])
def addDocument():
    if request.headers['Content-Type'] == 'application/json':
        payload=json.dumps(request.json)
        data = json.loads(payload)
        uniqueid = random.randint(1,101)
        data['id'] = uniqueid
        payload=json.dumps(data)
        doc_index=request.json.get("Category")
        print("index:{}".format(doc_index))
        print(payload)
        res = es.index(index="cmprideshare", doc_type='blogpost', body=payload)
        result=res['result'];
        return jsonify({'result':result})
    else:
        return "415 Unsupported!!"

def rreplace(s, old, new, occurrence):
    li = s.rsplit(old, occurrence)
    return new.join(li)

@app.route('/api/getSlackRequest', methods=['GET'])
def processSlackRequest():
    user = request.args.get('user_name')  
    response_url = request.args.get('response_url')  
    query_str = request.args.get('text')  
    print(response_url)
    print("========")
    print(query_str)
    res=requests.get('http://xx:8080/api/search/slack/all/'+query_str)
    print(res.json())
    #attachmentText = "Finding information for *" + query_str+"*"
    attachments = ''
    entries=[]
    for item in res.json():
        print( item['title'])
        #attachmentText = attachmentText + "\n" + item['title'] + " <http://google.com>"
        entry={}
        entry['color']="#7CD197"
        entry['title']=item["title"]
        entry['title_link']="https://google.com"
        entry['text']="This is samepl"
        entries.append(entry)
	    
    #attachments = attachments + '{"color": "#7CD197", "title":"'+item["title"]+'", "title_url": "http://google.com","text":"THis is text"},'

    #attachments = rreplace(attachments,',','',1)
    #attachments = "[" + attachments + "]"
    #print(attachments)
    #print getDocuments("sale","sale")
    #return "Finding information for *" + query_str +"*"
    attachments = json.dumps(entries)
    print(json.dumps({"attachments":attachments}))
    return Response(json.dumps({"attachments":entries}), mimetype='application/json') 
    #return Response(json.dumps({"attachments":[{"color": "#7CD197", "title":"Colleague market place", "text": attachmentText}]}), mimetype='application/json') 

@app.route('/api/search/slack/<indexS>/<searchstring>')
def getDocumentsForSlack(indexS, searchstring):
        res=None
        search_tags= searchstring.split(",")
        if (indexS=="all"):
            res = es.search(index="cmp*", body={"query": {"match": {"tags": json.dumps(search_tags)}}})
        else:
            #res = es.search(index=indexS, body={"query": {"match": {"tags": searchstring}}})
            res = es.search(index=indexS, body={"query": {"match": {"tags": json.dumps(search_tags)}}})
        docList = []
        print("Got %d Hits:" % res['hits']['total'])
        for hit in res['hits']['hits']:
            # print("%(timestamp)s %(author)s: %(text)s" % hit["_source"])
            # docList.append(json.dumps(hit["_source"]))
            print(hit["_source"])
            data={}
            data["title"]=hit["_source"]["Title"]
            data["id"]=hit["_source"]["id"]
            docList.append(data)
            #print(data)
        jsondumpstr = json.dumps(docList)
        print(jsondumpstr)
        # return jsonify({'matchingdocs': jsondumpstr})
        return Response(jsondumpstr, mimetype='application/json')


if __name__ == '__main__':
    #if not os.path.exists('db.sqlite'):
    #    db.create_all()
    app.run(debug=True)
