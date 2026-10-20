import ast

from django import template

register = template.Library()
from CPABSEApp.models import DataStorage
from CPABSEApp.views import encrypt
from CPABSEApp.views import decrypt


@register.simple_tag()
def getdate(fid):
    query = DataStorage.objects.all().filter(id=fid)
    if query:
        for row in query:
            db_date = row.UDate
        password = "abacs"
        # Let us decrypt using our original password
        # print("type :", type(bytes.decode(db_date)))
        decrypted = decrypt(ast.literal_eval(bytes.decode(db_date)), password)
    return bytes.decode(decrypted)


@register.simple_tag()
def getcontents(fid):
    query = DataStorage.objects.all().filter(id=fid)
    if query:
        for row in query:
            db_content = row.FileContent
        password = "abacs"
        # Let us decrypt using our original password
        decrypted = decrypt(ast.literal_eval(bytes.decode(db_content)), password)
    return bytes.decode(decrypted)

