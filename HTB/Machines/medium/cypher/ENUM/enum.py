from requests import *

def togli_slash(stringa):
    return stringa.replace('/','_')

s = Session()

URL="http://cypher.htb"

PATHS=[
    "/about",
    "/about.html",
    "/api",
    "/api/docs",
    "/api/api",
    "/demo",
    "/demo/login",
    "/api/demo",
    "/login.html",
    "/login"
    "/testing"
]

for p in PATHS:
    nome = togli_slash(p)
    name = "{}.txt".format(nome)
    with open(name, 'w') as f:
        # response = s.get(URL+p)
        response = s.options(URL+p)
        f.write(response.text)
