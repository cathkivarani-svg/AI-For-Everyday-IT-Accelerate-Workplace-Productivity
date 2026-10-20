import os
import ast
import codecs
import random
import hashlib
import datetime
import pyaes, pbkdf2, binascii, secrets
from re import search
from datetime import datetime
from .sendmail import sendmail
from .models import IoTDevices
from .models import Transaction
from .models import KGC
from .models import CloudServer
from .models import Search
from .models import KeyRequest
from .models import IoTDeviceFiles
from .models import OwnerRegistration
from .models import DataStorage
from .models import IOTKeys
from .models import Attacker
from django.db.models import Q
from django.db.models import Max
from django.contrib import messages
from django.shortcuts import render
from django.http import HttpResponse
from django.http import JsonResponse
from base64 import b64encode, b64decode
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from django.core.files.storage import FileSystemStorage

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# Create your views here.
def index(request):
    return render(request, "CPABSEApp/index.html")


def owner_register(request):
    if request.method == "POST":
        username = request.POST["userid"]
        pwd = request.POST["pass"]
        uname = request.POST["uname"]
        dob = request.POST["dob"]
        gender = request.POST["gender"]
        email = request.POST["email"]
        mobile = request.POST["mobile"]
        address = request.POST["address"]
        pincode = request.POST["pincode"]
        owner_type = request.POST["owner_type"]
        photo = request.FILES['imgFile']
        askQuery = OwnerRegistration.objects.all().filter(UserName=username)
        if askQuery:
            messages.success(request, "Data Owner Already Registered.")
        else:
            status = "Waiting"
            authorize_key = "Waiting"
            fs = FileSystemStorage()
            filename = fs.save(photo.name, photo)
            uploaded_file_url = fs.url(filename)
            insertQuery = OwnerRegistration(UserName=username, Pwd=pwd, Name=uname, Gender=gender, Dob=dob, Email=email,
                                            MobileNo=mobile, Address=address, PinCode=pincode, OwnerType=owner_type,
                                            ProfileImg=uploaded_file_url, AuthorizeKey=authorize_key, Status=status)
            insertQuery.save()
            if insertQuery.save:
                messages.success(request, "Data Owner Registered Successfully.")
            else:
                messages.success(request, "Data Owner Register Failed.")
    return render(request, "CPABSEApp/OwnerRegister.html")


def owner_login(request):
    if request.method == "POST":
        uname = request.POST['userid']
        pwd = request.POST['pass']
        akey = request.POST['akey']
        query = OwnerRegistration.objects.all().filter(UserName=uname, Pwd=pwd)
        if query:
            for reg in query:
                status = reg.Status
            if status == "Authorized":
                query1 = OwnerRegistration.objects.all().filter(UserName=uname, Pwd=pwd, AuthorizeKey=akey)
                if query1:
                    for reg1 in query1:
                        name = reg1.Name
                        username = reg1.UserName
                    request.session['user'] = name
                    request.session['uid'] = username
                    strUser = request.session['user']
                    askQuery = OwnerRegistration.objects.all().filter(UserName=username, Pwd=pwd)
                    return render(request, "CPABSEApp/OwnerHome.html", {"sessionUser": strUser, 'askQuery': askQuery})
                else:
                    messages.success(request, "Wrong Authorize Key, Try Again.")
                    return render(request, "CPABSEApp/OwnerAuthorize2.html")
            elif status == "Waiting":
                messages.success(request, "Please Wait For Key Generation Center To Authorize You !!!")
                return render(request, "CPABSEApp/OwnerAuthorize1.html")
            else:
                messages.success(request, "Please Wait For Key Generation Center To Authorize You !!!")
                return render(request, "CPABSEApp/OwnerAuthorize.html")
        else:
            messages.success(request, "Invalid User Name and Password")
        return render(request, "CPABSEApp/WrongLogin.html")
    else:
        if 'user' in request.session:
            strUser = request.session['user']
            uname = request.session['uid']
            askQuery = OwnerRegistration.objects.all().filter(UserName=uname, Name=strUser)
            return render(request, "CPABSEApp/OwnerHome.html", {"sessionUser": strUser, 'askQuery': askQuery})
        else:
            return render(request, "CPABSEApp/OwnerLogin.html")


def owner_home(request):
    if 'user' in request.session:
        strUser = request.session['user']
        uname = request.session['uid']
        askQuery = OwnerRegistration.objects.all().filter(UserName=uname, Name=strUser)
        if askQuery:
            return render(request, "CPABSEApp/OwnerHome.html", {"sessionUser": strUser, "askQuery": askQuery})
    else:
        return render(request, "CPABSEApp/OwnerLogin.html")


def owner_profile(request):
    if 'user' in request.session:
        strUser = request.session['user']
        uname = request.session['uid']
        askQuery = OwnerRegistration.objects.all().filter(UserName=uname, Name=strUser)
        if askQuery:
            return render(request, "CPABSEApp/OwnerProfile.html", {"sessionUser": strUser, "askQuery": askQuery})
    else:
        return render(request, "CPABSEApp/OwnerLogin.html")


def owner_view_files(request):
    if 'user' in request.session:
        strUser = request.session['user']
        askQuery = DataStorage.objects.all().order_by('id')
        if askQuery:
            return render(request, "CPABSEApp/OwnerViewFiles.html", {"sessionUser": strUser, "askQuery": askQuery})
        else:
            return render(request, "CPABSEApp/OwnerViewFiles.html", {"sessionUser": strUser})
    else:
        return render(request, "CPABSEApp/OwnerLogin.html")


def owner_search_files(request):
    if 'user' in request.session:
        strUser = request.session['user']
        uname = request.session['uid']
        if request.method == "POST":
            keyword = request.POST["txtKeyword"]
            now = datetime.now()
            cur_date = now.strftime("%Y-%m-%d %H:%M:%S")
            password = "abacs"
            task = "Search"
            mySearch =""
            insert_query = Transaction(Owner=uname, FileName=keyword, Task=task, TDate=cur_date)
            insert_query.save()
            insert_query = Search(Owner=uname, Keyword=keyword, SDate=cur_date)
            insert_query.save()
            askQuery = DataStorage.objects.all().order_by('id')
            if askQuery:
                for row in askQuery:
                    dbFileName = row.FileName
                    dbFileContent = row.FileContent
                    # Let us decrypt using our original password
                    decrypted_content = decrypt(ast.literal_eval(bytes.decode(dbFileContent)), password)
                    decrypted_content = bytes.decode(decrypted_content)
                    if search(keyword, decrypted_content) or search(keyword, dbFileName):
                        askQuery1 = DataStorage.objects.all().filter(FileName=dbFileName, FStatus = "Original").order_by('id')
                        if askQuery1:
                            for row1 in askQuery1:
                                dbRanks = row1.Ranks
                            Ranks = dbRanks + 1
                            rankUpdate = DataStorage.objects.filter(FileName=dbFileName).update(Ranks=Ranks)
                        return render(request, "CPABSEApp/OwnerSearchFiles.html", {"sessionUser": strUser, "askQuery1": askQuery1})
                    else:
                        mySearch ="File Not"
                        return render(request, "CPABSEApp/OwnerSearchFiles.html", {"sessionUser": strUser, "mySearch": mySearch})
            else:
                mySearch = "File Not"
                return render(request, "CPABSEApp/OwnerSearchFiles.html", {"sessionUser": strUser, "mySearch": mySearch})
        else:
            return render(request, "CPABSEApp/OwnerSearchFile.html", {"sessionUser": strUser})
    else:
        return render(request, "CPABSEApp/OwnerLogin.html")


def download_search_file(request, filename):
    if 'user' in request.session:
        strUser = request.session['user']
        uname = request.session['uid']
        return render(request, "CPABSEApp/OwnerDownloadSearchFile.html", {"sessionUser": strUser, "FileName": filename})
    else:
        return render(request, "CPABSEApp/OwnerLogin.html")


def download_file(request):
    if 'user' in request.session:
        strUser = request.session['user']
        uname = request.session['uid']
        if request.method == "POST":
            filename = request.POST["filename"]
            if 'privatekey' not in request.POST:
                privatekey = ""
            else:
                privatekey = request.POST["privatekey"]
            attMessage = ""
            Message = ""
            Keyword = ""
            trapdoor = ""
            publickey = ""
            privatekey = ""
            d1trapdoor = ""
            d1publickey = ""
            d1privatekey = ""
            d2trapdoor = ""
            d2publickey = ""
            d2privatekey = ""
            status = ""
            askQuery = DataStorage.objects.all().filter(FileName=filename)
            if askQuery:
                for row in askQuery:
                    Keyword = row.Keyword
                    status = row.FStatus
                if status == "Attacked":
                    attMessage = "File Content Attacked You Will Not Be Able To Download " + filename + " !!!"
                    return render(request, "CPABSEApp/OwnerDownloadedSearchFile.html", {"sessionUser": strUser, "Message": attMessage})
                else:
                    askQuery1 = KeyRequest.objects.all().filter(FileName=filename, Owner=uname)
                    if askQuery1:
                        for row1 in askQuery1:
                            privatekey = row1.PrivateKey
                            trapdoor = row1.Trapdoor
                            publickey = row1.PublicKey
                        if privatekey == "Generate Query":
                            Message = "Private Key Not Generated !!!"
                        elif privatekey == "No":
                            Message = "Private Key Not Requested !!!"
                        else:
                            if trapdoor == "Generate Trapdoors":
                                Message = "Trapdoors Not Generated !!!"
                            elif trapdoor == "No":
                                Message = "Trapdoors Not Requested !!!"
                            else:
                                if publickey == "Generate Query":
                                    Message = "Public Key Not Generated !!!"
                                elif publickey == "No":
                                    Message = "Public Key Not Requested !!!"
                                else:
                                    askQuery2 = IOTKeys.objects.all().filter(FileName=filename)
                                    if askQuery2:
                                        for row2 in askQuery2:
                                            d1privatekey = row2.D1PrivateKey
                                            d1trapdoor = row2.D1Trapdoor
                                            d1publickey = row2.D1PublicKey
                                            d2privatekey = row2.D2PrivateKey
                                            d2trapdoor = row2.D2Trapdoor
                                            d2publickey = row2.D2PublicKey
                                        if d1publickey == d2publickey:
                                            if d1trapdoor == d2trapdoor:
                                                if d1privatekey == d2privatekey:
                                                    fileData = [filename, Keyword, trapdoor, d2publickey, privatekey]
                                                    return render(request, "CPABSEApp/OwnerDownloadedSearchFile.html",
                                                                  {"sessionUser": strUser, "fileData": fileData})
                                                else:
                                                    attMessage = "Private Key Attacked You Will Not Be Able To Download " + filename + " !!!"
                                                    return render(request, "CPABSEApp/OwnerDownloadedSearchFile.html",
                                                                  {"sessionUser": strUser, "Message": attMessage})
                                            else:
                                                attMessage = "Trapdoors Attacked You Will Not Be Able To Download " + filename + " !!!"
                                                return render(request, "CPABSEApp/OwnerDownloadedSearchFile.html",
                                                              {"sessionUser": strUser, "Message": attMessage})
                                        else:
                                            attMessage = "Public Key Attacked You Will Not Be Able To Download " + filename + " !!!"
                                            return render(request, "CPABSEApp/OwnerDownloadedSearchFile.html",
                                                          {"sessionUser": strUser, "Message": attMessage})
                    else:
                        Message = "Keys Not Requested !!!"
                        return render(request, "CPABSEApp/OwnerDownloadedSearchFile.html", {"sessionUser": strUser, "Message": Message})
            else:
                Message ="File Doesn't Exist !!!"
                return render(request, "CPABSEApp/OwnerDownloadedSearchFile.html", {"sessionUser": strUser, "Message": Message})
        else:
            return render(request, "CPABSEApp/OwnerDownloadSearchFile.html", {"sessionUser": strUser})
    else:
        return render(request, "CPABSEApp/OwnerLogin.html")


def downloaded_file(request):
    if 'user' in request.session:
        strUser = request.session['user']
        uname = request.session['uid']
        if request.method == "POST":
            filename = request.POST["filename"]
            keyword = request.POST["keyword"]
            trapdoor = request.POST["trapdoor"]
            publickey = request.POST["publickey"]
            privatekey = request.POST["privatekey"]
            now = datetime.now()
            cur_date = now.strftime("%Y-%m-%d %H:%M:%S")
            attMessage = ""
            Message = ""
            status = ""
            askQuery = DataStorage.objects.all().filter(FileName=filename, Keyword=keyword)
            if askQuery:
                for row in askQuery:
                    askQuery1 = IOTKeys.objects.all().filter(FileName=filename)
                    if askQuery1:
                        for row1 in askQuery1:
                            dbContent = row.FileContent
                            dbPublicKey = row1.D1PublicKey
                            dbPrivateKey = row1.D1PrivateKey
                            dbTrapdoor = row1.D1Trapdoor
                            if dbPrivateKey == privatekey:
                                if dbTrapdoor == trapdoor:
                                    if dbPublicKey == publickey:
                                        dbRanks = row.Ranks
                                        Ranks = dbRanks + 1
                                        rankUpdate = DataStorage.objects.filter(FileName=filename).update(Ranks=Ranks)
                                        now = datetime.now()
                                        cur_date = now.strftime("%Y-%m-%d %H:%M:%S")
                                        task = "Download"
                                        password = "abacs"
                                        insert_query = Transaction(Owner=uname, FileName=filename, Task=task, TDate=cur_date)
                                        insert_query.save()
                                        # Let us decrypt using our original password
                                        decrypted_content = decrypt(ast.literal_eval(bytes.decode(dbContent)), password)
                                        decrypted_content = bytes.decode(decrypted_content)
                                        fileData = [decrypted_content]
                                        return render(request, "CPABSEApp/OwnerDownloadedFile.html",
                                                      {"sessionUser": strUser, "fileData": fileData})
                                    else:
                                        status = "Public Key Attack"
                                        insert_query = Attacker(Owner=uname, FileName=filename, AttackKey=publickey,
                                                                   ADate=cur_date, AttackType=status)
                                        insert_query.save()
                                        attMessage = "Public Key Mismatch !!!"
                                        return render(request, "CPABSEApp/OwnerDownloadedFile.html",
                                                      {"sessionUser": strUser, "Message": attMessage})
                                else:
                                    status = "Trapdoors Attack"
                                    insert_query = Attacker(Owner=uname, FileName=filename, AttackKey=trapdoor,
                                                            ADate=cur_date, AttackType=status)
                                    insert_query.save()
                                    attMessage = "Trapdoors Mismatch !!!"
                                    return render(request, "CPABSEApp/OwnerDownloadedFile.html",
                                                  {"sessionUser": strUser, "Message": attMessage})
                            else:
                                status = "Private Key Attack"
                                insert_query = Attacker(Owner=uname, FileName=filename, AttackKey=privatekey,
                                                        ADate=cur_date, AttackType=status)
                                insert_query.save()
                                attMessage = "Private Key Mismatch !!!"
                                return render(request, "CPABSEApp/OwnerDownloadedFile.html",
                                              {"sessionUser": strUser, "Message": attMessage})
                    else:
                        Message ="File Doesn't Exist !!!"
                        return render(request, "CPABSEApp/OwnerDownloadedFile.html", {"sessionUser": strUser, "Message": Message})
            else:
                status = "Keyword Creation Attack"
                insert_query = Attacker(Owner=uname, FileName=filename, AttackKey=keyword,
                                        ADate=cur_date, AttackType=status)
                insert_query.save()
                attMessage = "Keyword Creation Mismatch !!!"
                return render(request, "CPABSEApp/OwnerDownloadedFile.html",
                              {"sessionUser": strUser, "Message": attMessage})
        else:
            return render(request, "CPABSEApp/OwnerDownloadSearchFile.html", {"sessionUser": strUser})
    else:
        return render(request, "CPABSEApp/OwnerLogin.html")


def owner_req_public_key(request):
    if 'user' in request.session:
        strUser = request.session['user']
        uname = request.session['uid']
        if request.method == "POST":
            iot_device = request.POST["iot_device"]
            filename = request.POST["filename"]
            Message = ""
            publickey = ""
            status = "Requested"
            askQuery = DataStorage.objects.all().filter(FileName=filename, IoTDevice=iot_device)
            if askQuery:
                askQuery1 = KeyRequest.objects.all().filter(Owner=uname, IoTDevice=iot_device, FileName=filename)
                if askQuery1:
                    for row1 in askQuery1:
                        publickey = row1.PublicKey
                    if publickey == status:
                        Message = "Request Already Sent !!!"
                    elif publickey == "No":
                        keyUpdate = KeyRequest.objects.filter(Owner=uname, IoTDevice=iot_device, FileName=filename).update(PublicKey=status)
                        Message = "Public Key Request Sent !!"
                    else:
                        Message = "Key Request Already Sent !!!"
                    return render(request, "CPABSEApp/OwnerReqPublicKey.html",
                                  {"sessionUser": strUser, "Message": Message})
                else:
                    insertQuery = KeyRequest(Owner=uname, IoTDevice=iot_device, FileName=filename, PrivateKey="No",
                                             Trapdoor="No", PublicKey=status)
                    insertQuery.save()
                    if insertQuery.save:
                        Message = "Public Key Request Sent !!"
                    return render(request, "CPABSEApp/OwnerReqPublicKey.html",
                                  {"sessionUser": strUser, "Message": Message})
            else:
                Message = "File Doesn't Exist!!!"
                return render(request, "CPABSEApp/OwnerReqPublicKey.html", {"sessionUser": strUser, "Message": Message})
        else:
            return render(request, "CPABSEApp/OwnerReqPublicKey.html", {"sessionUser": strUser})
    else:
        return render(request, "CPABSEApp/OwnerLogin.html")


def owner_req_private_key(request):
    if 'user' in request.session:
        strUser = request.session['user']
        uname = request.session['uid']
        if request.method == "POST":
            iot_device = request.POST["iot_device"]
            filename = request.POST["filename"]
            Message = ""
            privatekey = ""
            status = "Generate Key"
            askQuery = DataStorage.objects.all().filter(FileName=filename, IoTDevice=iot_device)
            if askQuery:
                askQuery1 = KeyRequest.objects.all().filter(Owner=uname, IoTDevice=iot_device, FileName=filename)
                if askQuery1:
                    for row1 in askQuery1:
                        privatekey = row1.PrivateKey
                    if privatekey == status:
                        Message = "Request Already Sent !!!"
                    elif privatekey == "No":
                        keyUpdate = KeyRequest.objects.filter(Owner=uname, IoTDevice=iot_device, FileName=filename).update(PrivateKey=status)
                        Message = "Private Key Request Sent !!"
                    else:
                        Message = "Key Request Already Sent !!!"
                    return render(request, "CPABSEApp/OwnerReqPrivateKey.html",
                                  {"sessionUser": strUser, "Message": Message})
                else:
                    insertQuery = KeyRequest(Owner=uname, IoTDevice=iot_device, FileName=filename, PrivateKey=status,
                                             Trapdoor="No", PublicKey="No")
                    insertQuery.save()
                    if insertQuery.save:
                        Message = "Private Key Request Sent !!"
                    return render(request, "CPABSEApp/OwnerReqPrivateKey.html",
                                  {"sessionUser": strUser, "Message": Message})
            else:
                Message = "File Doesn't Exist!!!"
                return render(request, "CPABSEApp/OwnerReqPrivateKey.html", {"sessionUser": strUser, "Message": Message})
        else:
            return render(request, "CPABSEApp/OwnerReqPrivateKey.html", {"sessionUser": strUser})
    else:
        return render(request, "CPABSEApp/OwnerLogin.html")


def owner_req_trapdoor(request):
    if 'user' in request.session:
        strUser = request.session['user']
        uname = request.session['uid']
        if request.method == "POST":
            iot_device = request.POST["iot_device"]
            filename = request.POST["filename"]
            Message = ""
            trapdoor = ""
            status = "Generate Trapdoors"
            askQuery = DataStorage.objects.all().filter(FileName=filename, IoTDevice=iot_device)
            if askQuery:
                askQuery1 = KeyRequest.objects.all().filter(Owner=uname, IoTDevice=iot_device, FileName=filename)
                if askQuery1:
                    for row1 in askQuery1:
                        trapdoor = row1.Trapdoor
                    if trapdoor == status:
                        Message = "Generating Trapdoors Already Sent !!!"
                    elif trapdoor == "No":
                        keyUpdate = KeyRequest.objects.filter(Owner=uname, IoTDevice=iot_device, FileName=filename).update(Trapdoor=status)
                        Message = "Generating Trapdoors Sent !!"
                    else:
                        Message = "Generating Trapdoors Already Sent !!!"
                    return render(request, "CPABSEApp/OwnerReqTrapdoor.html",
                                  {"sessionUser": strUser, "Message": Message})
                else:
                    insertQuery = KeyRequest(Owner=uname, IoTDevice=iot_device, FileName=filename, PrivateKey="No",
                                             Trapdoor=status, PublicKey="No")
                    insertQuery.save()
                    if insertQuery.save:
                        Message = "Generating Trapdoors Sent !!"
                    return render(request, "CPABSEApp/OwnerReqTrapdoor.html",
                                  {"sessionUser": strUser, "Message": Message})
            else:
                Message = "File Doesn't Exist!!!"
                return render(request, "CPABSEApp/OwnerReqTrapdoor.html", {"sessionUser": strUser, "Message": Message})
        else:
            return render(request, "CPABSEApp/OwnerReqTrapdoor.html", {"sessionUser": strUser})
    else:
        return render(request, "CPABSEApp/OwnerLogin.html")


def owner_res_public_key(request):
    if 'user' in request.session:
        strUser = request.session['user']
        uname = request.session['uid']
        if request.method == "POST":
            iot_device = request.POST["iot_device"]
            filename = request.POST["filename"]
            Message = ""
            publickey = ""
            status = "Requested"
            askQuery = DataStorage.objects.all().filter(FileName=filename)
            if askQuery:
                askQuery1 = KeyRequest.objects.all().filter(Owner=uname, FileName=filename)
                if askQuery1:
                    for row1 in askQuery1:
                        publickey = row1.PublicKey
                    if publickey == "NO":
                        Message = "Public Key Not Requested !!!"
                    elif publickey == "Requested":
                        Message = "Public Key Not Permitted !!!"
                    elif publickey == "Permitted":
                        askQuery2 = IOTKeys.objects.all().filter(IoTDevice=iot_device, FileName=filename)
                        if askQuery2:
                            for row2 in askQuery2:
                                d1publickey = row2.D1PublicKey
                                d2publickey = row2.D2PublicKey
                            if d1publickey == d2publickey:
                                Message = "Public Key : " + d1publickey
                            else:
                                Message = "Public Key Attacked !!!"
                    return render(request, "CPABSEApp/OwnerResPublicKey.html", {"sessionUser": strUser, "Message": Message})
                else:
                    Message = "Public Key Not Requested !!!"
                    return render(request, "CPABSEApp/OwnerResPublicKey.html", {"sessionUser": strUser, "Message": Message})
            else:
                Message = "File Not Found !!!"
                return render(request, "CPABSEApp/OwnerResPublicKey.html", {"sessionUser": strUser, "Message": Message})
        else:
            return render(request, "CPABSEApp/OwnerResPublicKey.html", {"sessionUser": strUser})
    else:
        return render(request, "CPABSEApp/OwnerLogin.html")


def owner_res_private_key(request):
    if 'user' in request.session:
        strUser = request.session['user']
        uname = request.session['uid']
        if request.method == "POST":
            iot_device = request.POST["iot_device"]
            filename = request.POST["filename"]
            Message = ""
            privatekey = ""
            status = "Generate Key"
            askQuery = DataStorage.objects.all().filter(FileName=filename)
            if askQuery:
                askQuery1 = KeyRequest.objects.all().filter(Owner=uname, FileName=filename)
                if askQuery1:
                    for row1 in askQuery1:
                        privatekey = row1.PrivateKey
                    if privatekey == "Generate Key":
                        Message = "Private Key Not Generated !!!"
                    else:
                        askQuery2 = IOTKeys.objects.all().filter(IoTDevice=iot_device, FileName=filename)
                        if askQuery2:
                            for row2 in askQuery2:
                                d1privatekey = row2.D1PrivateKey
                                d2privatekey = row2.D2PrivateKey
                            if d1privatekey == d2privatekey:
                                Message = "Private Key : " + d1privatekey
                            else:
                                Message = "Private Key Attacked !!!"
                    return render(request, "CPABSEApp/OwnerResPrivateKey.html", {"sessionUser": strUser, "Message": Message})
                else:
                    Message = "Private Key Not Requested !!!"
                    return render(request, "CPABSEApp/OwnerResPrivateKey.html", {"sessionUser": strUser, "Message": Message})
            else:
                Message = "File Not Found !!!"
                return render(request, "CPABSEApp/OwnerResPrivateKey.html", {"sessionUser": strUser, "Message": Message})
        else:
            return render(request, "CPABSEApp/OwnerResPrivateKey.html", {"sessionUser": strUser})
    else:
        return render(request, "CPABSEApp/OwnerLogin.html")


def owner_res_trapdoor(request):
    if 'user' in request.session:
        strUser = request.session['user']
        uname = request.session['uid']
        if request.method == "POST":
            iot_device = request.POST["iot_device"]
            filename = request.POST["filename"]
            Message = ""
            trapdoor = ""
            status = "Generate Trapdoors"
            askQuery = DataStorage.objects.all().filter(FileName=filename)
            if askQuery:
                askQuery1 = KeyRequest.objects.all().filter(Owner=uname, FileName=filename)
                if askQuery1:
                    for row1 in askQuery1:
                        trapdoor = row1.Trapdoor
                    if trapdoor == "Generate Trapdoors":
                        Message = "Trapdoors Not Generated !!!"
                    else:
                        askQuery2 = IOTKeys.objects.all().filter(IoTDevice=iot_device, FileName=filename)
                        if askQuery2:
                            for row2 in askQuery2:
                                d1trapdoor = row2.D1Trapdoor
                                d2trapdoor = row2.D2Trapdoor
                            if d1trapdoor == d2trapdoor:
                                Message = "Trapdoors : " + d1trapdoor
                            else:
                                Message = "Trapdoors Attacked !!!"
                    return render(request, "CPABSEApp/OwnerResTrapdoor.html",
                                  {"sessionUser": strUser, "Message": Message})
                else:
                    Message = "Trapdoors Not Requested !!!"
                    return render(request, "CPABSEApp/OwnerResTrapdoor.html",
                                  {"sessionUser": strUser, "Message": Message})
            else:
                Message = "File Not Found !!!"
                return render(request, "CPABSEApp/OwnerResTrapdoor.html",
                              {"sessionUser": strUser, "Message": Message})
        else:
            return render(request, "CPABSEApp/OwnerResTrapdoor.html", {"sessionUser": strUser})
    else:
        return render(request, "CPABSEApp/OwnerLogin.html")


def owner_download_file(request):
    if 'user' in request.session:
        strUser = request.session['user']
        uname = request.session['uid']
        if request.method == "POST":
            filename = request.POST["filename"]
            if 'keyword' not in request.POST:
                keyword = ""
            else:
                keyword = request.POST["keyword"]
            attMessage = ""
            Message = ""
            keyword = ""
            trapdoor = ""
            publickey = ""
            privatekey = ""
            d1trapdoor = ""
            d1publickey = ""
            d1privatekey = ""
            d2trapdoor = ""
            d2publickey = ""
            d2privatekey = ""
            status = ""
            askQuery = DataStorage.objects.all().filter(FileName=filename, FStatus = "Original")
            if askQuery:
                for row in askQuery:
                    keyword = row.Keyword
                    status = row.FStatus
                if status == "Attacked":
                    attMessage = "File Content Attacked You Will Not Be Able To Download " + filename + " !!!"
                    return render(request, "CPABSEApp/OwnerDownloadFile.html", {"sessionUser": strUser, "Message": attMessage})
                else:
                    askQuery1 = KeyRequest.objects.all().filter(FileName=filename, Owner=uname)
                    if askQuery1:
                        for row1 in askQuery1:
                            trapdoor = row1.Trapdoor
                            publickey = row1.PublicKey
                            privatekey = row1.PrivateKey
                        if privatekey == "Generate Query":
                            Message = "Private Key Not Generated !!!"
                        elif privatekey == "No":
                            Message = "Private Key Not Requested !!!"
                        else:
                            if trapdoor == "Generate Trapdoors":
                                Message = "Trapdoors Not Generated !!!"
                            elif trapdoor == "No":
                                Message = "Trapdoors Not Requested !!!"
                            else:
                                if publickey == "Generate Query":
                                    Message = "Public Key Not Generated !!!"
                                elif publickey == "No":
                                    Message = "Public Key Not Requested !!!"
                                else:
                                    askQuery2 = IOTKeys.objects.all().filter(FileName=filename)
                                    if askQuery2:
                                        for row2 in askQuery2:
                                            d1privatekey = row2.D1PrivateKey
                                            d1trapdoor = row2.D1Trapdoor
                                            d1publickey = row2.D1PublicKey
                                            d2privatekey = row2.D2PrivateKey
                                            d2trapdoor = row2.D2Trapdoor
                                            d2publickey = row2.D2PublicKey
                                        if d1publickey == d2publickey:
                                            if d1trapdoor == d2trapdoor:
                                                if d1privatekey == d2privatekey:
                                                    fileData = [filename, keyword, trapdoor, d2publickey, privatekey]
                                                    return render(request, "CPABSEApp/OwnerDownloadedSearchFile.html",
                                                                  {"sessionUser": strUser, "fileData": fileData})
                                                else:
                                                    attMessage = "Private Key Attacked You Will Not Be Able To Download " + filename + " !!!"
                                                    return render(request, "CPABSEApp/OwnerDownloadFile.html",
                                                                  {"sessionUser": strUser, "Message": attMessage})
                                            else:
                                                attMessage = "Trapdoors Attacked You Will Not Be Able To Download " + filename + " !!!"
                                                return render(request, "CPABSEApp/OwnerDownloadFile.html",
                                                              {"sessionUser": strUser, "Message": attMessage})
                                        else:
                                            attMessage = "Public Key Attacked You Will Not Be Able To Download " + filename + " !!!"
                                            return render(request, "CPABSEApp/OwnerDownloadFile.html",
                                                          {"sessionUser": strUser, "Message": attMessage})
                    else:
                        Message = "Keys Not Requested !!!"
                        return render(request, "CPABSEApp/OwnerDownloadFile.html", {"sessionUser": strUser, "Message": Message})
            else:
                Message ="File Doesn't Exist !!!"
                return render(request, "CPABSEApp/OwnerDownloadFile.html", {"sessionUser": strUser, "Message": Message})
        else:
            return render(request, "CPABSEApp/OwnerDownloadFile.html", {"sessionUser": strUser})
    else:
        return render(request, "CPABSEApp/OwnerLogin.html")


def owner_puncturable_file(request):
    if 'user' in request.session:
        strUser = request.session['user']
        askQuery = DataStorage.objects.all().order_by('id')
        if askQuery:
            return render(request, "CPABSEApp/OwnerPuncturableFile.html", {"sessionUser": strUser, "askQuery": askQuery})
        else:
            return render(request, "CPABSEApp/OwnerPuncturableFile.html", {"sessionUser": strUser})
    else:
        return render(request, "CPABSEApp/OwnerLogin.html")


def owner_punctured_file(request, id):
    if 'user' in request.session:
        strUser = request.session['user']
        strStatus = "Punctured"
        statusUpdate = DataStorage.objects.filter(id=id).update(FStatus=strStatus)
        askQuery = DataStorage.objects.all().order_by('id')
        return render(request, "CPABSEApp/OwnerPuncturableFile.html", {"sessionUser": strUser, "askQuery": askQuery})
    else:
        return render(request, "CPABSEApp/OwnerLogin.html")


def owner_profile_image(request):
    if 'user' in request.session:
        strUser = request.session['user']
        uname = request.session['uid']
        if request.method == "POST":
            askQuery = OwnerRegistration.objects.all().filter(UserName=uname)
            if askQuery:
                photo = request.FILES['imgFile']
                fs = FileSystemStorage()
                filename = fs.save(photo.name, photo)
                uploaded_file_url = fs.url(filename)
                profileUpdate = OwnerRegistration.objects.filter(UserName=uname).update(ProfileImg=uploaded_file_url)
                if profileUpdate:
                    messages.success(request, "My Profile Image Updated Successfully.")
                else:
                    messages.success(request, "My Profile Image Not Updated.")
        else:
            askQuery = OwnerRegistration.objects.all().filter(UserName=uname)
        return render(request, "CPABSEApp/OwnerChangeProfileImage.html", {"sessionUser": strUser, 'askQuery': askQuery})
    else:
        return render(request, "CPABSEApp/OwnerLogin.html")


def owner_logout(request):
    if 'user' in request.session:
        del request.session['user']
        for key in list(request.session.keys()):
            del request.session[key]
        messages.success(request, "Logged Out Successfully.")
        return render(request, "CPABSEApp/OwnerLogin.html")
    else:
        return render(request, "CPABSEApp/OwnerLogin.html")


def iot_register(request):
    if request.method == "POST":
        username = request.POST["userid"]
        pwd = request.POST["pass"]
        iot_name = request.POST["iot_name"]
        email = request.POST["email"]
        address = request.POST["address"]
        pincode = request.POST["pincode"]
        iot_type = request.POST["iot_type"]
        photo = request.FILES['imgFile']
        status = "Waiting"
        authorize_key = "Waiting"
        askQuery = IoTDevices.objects.all().filter(UserName=username)
        if askQuery:
            messages.success(request, "IoT Device User Name Already Exits.")
        else:
            fs = FileSystemStorage()
            filename = fs.save(photo.name, photo)
            uploaded_file_url = fs.url(filename)
            insertQuery = IoTDevices(UserName=username, Pwd=pwd, Name=iot_name, Email=email, Address=address, PinCode=pincode, DeviceType=iot_type, ProfileImg=uploaded_file_url, AuthorizeKey=authorize_key, Status=status)
            insertQuery.save()
            if insertQuery.save:
                messages.success(request, "IoT Device Registered Successfully.")
            else:
                messages.success(request, "IoT Device Register Failed.")
    return render(request, "CPABSEApp/IoTRegister.html")


def iot_login(request):
    if request.method == "POST":
        uname = request.POST['userid']
        pwd = request.POST['pass']
        akey = request.POST['akey']
        query = IoTDevices.objects.all().filter(UserName=uname, Pwd=pwd)
        if query:
            for reg in query:
                status = reg.Status
            if status == "Authorized":
                query1 = IoTDevices.objects.all().filter(UserName=uname, Pwd=pwd, AuthorizeKey=akey)
                if query1:
                    for reg1 in query1:
                        name = reg1.Name
                        username = reg1.UserName
                    request.session['iot'] = name
                    request.session['did'] = username
                    strIoT = request.session['iot']
                    regIoT = IoTDevices.objects.all().filter(UserName=username, Pwd=pwd)
                    return render(request, "CPABSEApp/IoTHome.html", {"sessionIoT": strIoT, 'regIoT': regIoT})
                else:
                    messages.success(request, "Wrong Authorize Key, Try Again.")
                    return render(request, "CPABSEApp/IoTAuthorize2.html")
            elif status == "Waiting":
                messages.success(request, "Please Wait For Key Generation Center To Authorize You !!!")
                return render(request, "CPABSEApp/IoTAuthorize1.html")
            else:
                messages.success(request, "Please Wait For Key Generation Center To Authorize You !!!")
                return render(request, "CPABSEApp/IoTAuthorize.html")
        else:
            messages.success(request, "Invalid User Name and Password")
        return render(request, "CPABSEApp/WrongLogin.html")
    else:
        if 'iot' in request.session:
            strIoT = request.session['iot']
            uname = request.session['did']
            regIoT = IoTDevices.objects.all().filter(UserName=uname, Name=strIoT)
            return render(request, "CPABSEApp/IoTHome.html", {"sessionIoT": strIoT, 'regIoT': regIoT})
        else:
            return render(request, "CPABSEApp/IoTLogin.html")


def iot_home(request):
    if 'iot' in request.session:
        strIoT = request.session['iot']
        uname = request.session['did']
        regIoT = IoTDevices.objects.all().filter(UserName=uname, Name=strIoT)
        return render(request, "CPABSEApp/IoTHome.html", {"sessionIoT": strIoT, 'regIoT': regIoT})
    else:
        return render(request, "CPABSEApp/IoTLogin.html")


def upload_file(request):
    if 'iot' in request.session:
        strIoT = request.session['iot']
        return render(request, "CPABSEApp/IoTUploadFile.html", {"sessionIoT": strIoT})
    else:
        return render(request, "CPABSEApp/IoTLogin.html")


def upload_files(request):
    if 'iot' in request.session:
        strIoT = request.session['iot']
        uname = request.session['did']
        if request.method == "POST":
            filename = request.POST["filename"]
            contents = request.POST["contents"]
            keyword = request.POST["keyword"]
            public_key = request.POST["public_key"]
            request.session['fname'] = filename
            uploadQuery = DataStorage.objects.all().filter(FileName=filename)
            if uploadQuery:
                messages.success(request, "File Name Already Exists.")
            else:
                query = IoTDevices.objects.all().filter(UserName=uname)
                if query:
                    for reg in query:
                        status = reg.Status
                    if status == "Authorized":
                        password = "abacs"
                        # First let us encrypt secret message
                        encrypted = encrypt(contents, password)
                        # print("encrypted :", encrypted)
                        return render(request, "CPABSEApp/IoTUploadFiles.html",
                                      {"sessionIoT": strIoT, "file": filename, "cont": encrypted, "keyword": keyword, "key": public_key})
                    else:
                        messages.success(request, "Please Authorize To Key Generation Center !!.")
                        return render(request, "CPABSEApp/IoTUploadFile.html",
                                      {"sessionIoT": strIoT})
                else:
                    messages.success(request, "Data is not uploading.")
                    return render(request, "CPABSEApp/IoTUploadFile.html",
                                  {"sessionIoT": strIoT})
            return render(request, "CPABSEApp/IoTUploadFile.html", {"sessionIoT": strIoT})
        else:
            return render(request, "CPABSEApp/IoTUploadFile.html", {"sessionIoT": strIoT})
    else:
        return render(request, "CPABSEApp/IoTLogin.html")


def uploaded_files(request):
    if 'iot' in request.session:
        strIoT = request.session['iot']
        uname = request.session['did']
        if request.method == "POST":
            filename = request.POST["filename"]
            contents = request.POST["contents"]
            keyword = request.POST["keyword"]
            public_key = request.POST["public_key"]
            now = datetime.now()
            cur_date = now.strftime("%Y-%m-%d %H:%M:%S")
            request.session['fname'] = filename
            password = "abacs"
            # First let us encrypt secret message
            encrypt_date = encrypt(cur_date, password)
            # public_key = random.randint(100000000000,999999999999)
            rank = "0"
            task = "Upload"
            status = "Original"
            askQuery = IoTDeviceFiles.objects.all().filter(IoTDevice=uname, FileName=filename)
            if askQuery:
                messages.success(request, "The File is Already Uploaded.")
            else:
                insert_query = Transaction(Owner=uname, FileName=filename, Task=task, TDate=cur_date)
                insert_query.save()
                insert_query = DataStorage(FileName=filename, FileContent=contents, Keyword=keyword, PublicKey=public_key, Ranks=rank, UDate=encrypt_date, IoTDevice=uname, FStatus=status)
                insert_query.save()
                insert_query = IoTDeviceFiles(FileName=filename, IoTDevice=uname, FileContent=contents, Keyword=keyword, PublicKey=public_key, UDate=cur_date)
                insert_query.save()
                insert_query = IOTKeys(IoTDevice=uname, FileName=filename, D1PublicKey=public_key, D1PrivateKey="No", D1Trapdoor="No", D1Keyword=keyword, D2PublicKey=public_key, D2PrivateKey="No", D2Trapdoor="No", D2Keyword=keyword, KeyStatus="0")
                insert_query.save()
                if insert_query.save:
                    messages.success(request, "Data Uploaded Successfully !!!.")
                else:
                    messages.success(request, "Data is not Uploading.")
            return render(request, "CPABSEApp/IoTUploadedFiles.html", {"sessionIoT": strIoT})
        else:
            return render(request, "CPABSEApp/IoTUploadFile.html", {"sessionIoT": strIoT})
    else:
        return render(request, "CPABSEApp/IoTLogin.html")


def view_files(request):
    if 'iot' in request.session:
        strIoT = request.session['iot']
        uname = request.session['did']
        askQuery = DataStorage.objects.all().filter(IoTDevice=uname).order_by('id')
        if askQuery:
            return render(request, "CPABSEApp/IoTViewFiles.html", {"sessionIoT": strIoT, "askQuery": askQuery})
        else:
            return render(request, "CPABSEApp/IoTViewFiles.html", {"sessionIoT": strIoT})
    else:
        return render(request, "CPABSEApp/IoTLogin.html")


def viewed_files(request, filename):
    if 'iot' in request.session:
        strIoT = request.session['iot']
        uname = request.session['did']
        askQuery = DataStorage.objects.all().filter(IoTDevice=uname, FileName=filename).order_by('id')
        if askQuery:
            return render(request, "CPABSEApp/IoTViewedFiles.html", {"sessionIoT": strIoT, "askQuery": askQuery})
        else:
            return render(request, "CPABSEApp/IoTViewFiles.html", {"sessionIoT": strIoT})
    else:
        return render(request, "CPABSEApp/IoTLogin.html")


def verify_files(request):
    if 'iot' in request.session:
        strIoT = request.session['iot']
        uname = request.session['did']
        askQuery = DataStorage.objects.all().filter(IoTDevice=uname).order_by('id')
        if askQuery:
            return render(request, "CPABSEApp/IoTVerifyFiles.html", {"sessionIoT": strIoT, "askQuery": askQuery})
        else:
            return render(request, "CPABSEApp/IoTVerifyFiles.html", {"sessionIoT": strIoT})
    else:
        return render(request, "CPABSEApp/IoTLogin.html")


def verified_files(request, filename):
    if 'iot' in request.session:
        strIoT = request.session['iot']
        uname = request.session['did']
        askQuery = IOTKeys.objects.all().filter(IoTDevice=uname, FileName=filename)
        if askQuery:
            return render(request, "CPABSEApp/IoTVerifiedFiles.html", {"sessionIoT": strIoT, "askQuery": askQuery, "FileName": filename})
    else:
        return render(request, "CPABSEApp/IoTLogin.html")


def iot_logout(request):
    if 'iot' in request.session:
        del request.session['iot']
        for key in list(request.session.keys()):
            del request.session[key]
        messages.success(request, "Logged Out Successfully.")
        return render(request, "CPABSEApp/IoTLogin.html")
    else:
        return render(request, "CPABSEApp/IoTLogin.html")


def kgc_login(request):
    if request.method == "POST":
        uname = request.POST['userid']
        pwd = request.POST['pass']
        askQuery = KGC.objects.all().filter(Name=uname, Pass=pwd)
        if askQuery:
            for reg in askQuery:
                name = reg.Name
            request.session['kgcuser'] = name
            strKgc = request.session['kgcuser']
            return render(request, "CPABSEApp/KgcHome.html", {"sessionKgc": strKgc, "askQuery": askQuery})
        else:
            messages.success(request, "Invalid User Name and Password")
        return render(request, "CPABSEApp/WrongLogin.html")
    else:
        if 'kgcuser' in request.session:
            strKgc = request.session['kgcuser']
            askQuery = KGC.objects.all().filter(Name=strKgc)
            if askQuery:
                return render(request, "CPABSEApp/KgcHome.html", {"sessionKgc": strKgc, "askQuery": askQuery})
        else:
            return render(request, "CPABSEApp/KgcLogin.html")


def kgc_home(request):
    if 'kgcuser' in request.session:
        strKgc = request.session['kgcuser']
        askQuery = KGC.objects.all().filter(Name=strKgc)
        if askQuery:
            return render(request, "CPABSEApp/KgcHome.html", {"sessionKgc": strKgc, "askQuery": askQuery})
    else:
        return render(request, "CPABSEApp/KgcLogin.html")


def kgc_view_devices(request):
    if 'kgcuser' in request.session:
        strKgc = request.session['kgcuser']
        askQuery = IoTDevices.objects.all().order_by('id')
        if askQuery:
            return render(request, "CPABSEApp/KgcViewDevices.html", {"sessionKgc": strKgc, "askQuery": askQuery})
        else:
            return render(request, "CPABSEApp/KgcViewDevices.html", {"sessionKgc": strKgc})
    else:
        return render(request, "CPABSEApp/KgcLogin.html")


def kgc_verify_devices(request, id):
    if 'kgcuser' in request.session:
        strKgc = request.session['kgcuser']
        strStatus = "Authorized"
        strKey = privatekey_generate()
        emailQuery = IoTDevices.objects.all().filter(id=id)
        if emailQuery:
            for row in emailQuery:
                strName = row.Name
                strEmail = row.Email
            strMessage = "Hai " + strName + " Your Registration Authorized.\nYour Authorize Key is : " + strKey
            ans = sendmail(strEmail, strMessage)
        statusUpdate = IoTDevices.objects.filter(id=id).update(AuthorizeKey=strKey, Status=strStatus)
        askQuery = IoTDevices.objects.all().order_by('id')
        return render(request, "CPABSEApp/KgcViewDevices.html", {"sessionKgc": strKgc, "ans": ans, "askQuery": askQuery})
    else:
        return render(request, "CPABSEApp/KgcLogin.html")


def kgc_view_owners(request):
    if 'kgcuser' in request.session:
        strKgc = request.session['kgcuser']
        askQuery = OwnerRegistration.objects.all().order_by('id')
        if askQuery:
            return render(request, "CPABSEApp/KgcViewOwners.html", {"sessionKgc": strKgc, "askQuery": askQuery})
    else:
        return render(request, "CPABSEApp/KgcLogin.html")


def kgc_verify_owner(request, id):
    if 'kgcuser' in request.session:
        strKgc = request.session['kgcuser']
        strStatus = "Authorized"
        strKey = privatekey_generate()
        emailQuery = OwnerRegistration.objects.all().filter(id=id)
        if emailQuery:
            for row in emailQuery:
                strName = row.Name
                strEmail = row.Email
            strMessage = "Hai " + strName + " Your Registration Authorized.\nYour Authorize Key is : " + strKey
            ans = sendmail(strEmail, strMessage)
        statusUpdate = OwnerRegistration.objects.filter(id=id).update(AuthorizeKey=strKey, Status=strStatus)
        askQuery = OwnerRegistration.objects.all().order_by('id')
        return render(request, "CPABSEApp/KgcViewOwners.html", {"sessionKgc": strKgc, "ans": ans, "askQuery": askQuery})
    else:
        return render(request, "CPABSEApp/KgcLogin.html")


def kgc_owner_files(request):
    if 'kgcuser' in request.session:
        strKgc = request.session['kgcuser']
        askQuery = DataStorage.objects.all().filter(FStatus = "Original").order_by('id')
        if askQuery:
            return render(request, "CPABSEApp/KgcOwnerFiles.html", {"sessionKgc": strKgc, "askQuery": askQuery})
        else:
            return render(request, "CPABSEApp/KgcOwnerFiles.html", {"sessionKgc": strKgc})
    else:
        return render(request, "CPABSEApp/KgcLogin.html")


def kgc_viewed_file(request, filename):
    if 'kgcuser' in request.session:
        strKgc = request.session['kgcuser']
        askQuery = DataStorage.objects.all().filter(FileName=filename).order_by('id')
        if askQuery:
            return render(request, "CPABSEApp/KgcViewedFile.html", {"sessionKgc": strKgc, "askQuery": askQuery})
        else:
            return render(request, "CPABSEApp/KgcOwnerFiles.html", {"sessionKgc": strKgc})
    else:
        return render(request, "CPABSEApp/KgcLogin.html")


def kgc_files_with_publicKey(request):
    if 'kgcuser' in request.session:
        strKgc = request.session['kgcuser']
        askQuery = IOTKeys.objects.all().order_by('id')
        if askQuery:
            return render(request, "CPABSEApp/KgcFilesWithPublicKey.html",
                          {"sessionKgc": strKgc, "askQuery": askQuery})
        else:
            return render(request, "CPABSEApp/KgcFilesWithPublicKey.html", {"sessionKgc": strKgc})
    else:
        return render(request, "CPABSEApp/KgcLogin.html")


def kgc_publickey_permission(request):
    if 'kgcuser' in request.session:
        strKgc = request.session['kgcuser']
        askQuery = KeyRequest.objects.all().filter(~Q(PublicKey = "null")).order_by('id')
        if askQuery:
            return render(request, "CPABSEApp/KgcPublicKeyPermission.html",
                          {"sessionKgc": strKgc, "askQuery": askQuery})
        else:
            return render(request, "CPABSEApp/KgcPublicKeyPermission.html", {"sessionKgc": strKgc})
    else:
        return render(request, "CPABSEApp/KgcLogin.html")


def kgc_publicKey_permission_granted(request, id, filename):
    if 'kgcuser' in request.session:
        strKgc = request.session['kgcuser']
        strStatus = "Permitted"
        keyUpdate = KeyRequest.objects.filter(id=id, FileName=filename).update(PublicKey=strStatus)
        askQuery = KeyRequest.objects.all().filter(~Q(PublicKey = "null")).order_by('id')
        return render(request, "CPABSEApp/KgcPublicKeyPermission.html", {"sessionKgc": strKgc, "askQuery": askQuery})
    else:
        return render(request, "CPABSEApp/KgcLogin.html")


def kgc_generate_privateKey(request):
    if 'kgcuser' in request.session:
        strKgc = request.session['kgcuser']
        askQuery = KeyRequest.objects.all().filter(~Q(PrivateKey = "null")).order_by('id')
        if askQuery:
            return render(request, "CPABSEApp/KgcGeneratePrivateKey.html",
                          {"sessionKgc": strKgc, "askQuery": askQuery})
        else:
            return render(request, "CPABSEApp/KgcGeneratePrivateKey.html", {"sessionKgc": strKgc})
    else:
        return render(request, "CPABSEApp/KgcLogin.html")


def kgc_generated_privateKey(request, id, filename):
    if 'kgcuser' in request.session:
        strKgc = request.session['kgcuser']
        strKey = privatekey_generate()
        keyUpdate = IOTKeys.objects.filter(FileName=filename).update(D1PrivateKey=strKey, D2PrivateKey=strKey)
        keyUpdate = KeyRequest.objects.filter(id=id, FileName=filename).update(PrivateKey=strKey)
        askQuery = KeyRequest.objects.all().filter(~Q(PrivateKey = "null")).order_by('id')
        return render(request, "CPABSEApp/KgcGeneratePrivateKey.html", {"sessionKgc": strKgc, "askQuery": askQuery})
    else:
        return render(request, "CPABSEApp/KgcLogin.html")


def kgc_generate_trapdoor(request):
    if 'kgcuser' in request.session:
        strKgc = request.session['kgcuser']
        askQuery = KeyRequest.objects.all().filter(~Q(Trapdoor="null")).order_by('id')
        if askQuery:
            return render(request, "CPABSEApp/KgcGenerateTrapdoor.html",
                          {"sessionKgc": strKgc, "askQuery": askQuery})
        else:
            return render(request, "CPABSEApp/KgcGenerateTrapdoor.html", {"sessionKgc": strKgc})
    else:
        return render(request, "CPABSEApp/KgcLogin.html")


def kgc_generated_trapdoor(request, id, filename):
    if 'kgcuser' in request.session:
        strKgc = request.session['kgcuser']
        strKey = trapdoor_generate()
        keyUpdate = IOTKeys.objects.filter(FileName=filename).update(D1Trapdoor=strKey, D2Trapdoor=strKey)
        keyUpdate = KeyRequest.objects.filter(id=id, FileName=filename).update(Trapdoor=strKey)
        askQuery = KeyRequest.objects.all().filter(~Q(Trapdoor="null")).order_by('id')
        return render(request, "CPABSEApp/KgcGenerateTrapdoor.html",
                      {"sessionKgc": strKgc, "askQuery": askQuery})
    else:
        return render(request, "CPABSEApp/KgcLogin.html")


def kgc_logout(request):
    if 'kgcuser' in request.session:
        del request.session['kgcuser']
        for key in list(request.session.keys()):
            del request.session[key]
        messages.success(request, "Logged Out Successfully.")
        return render(request, "CPABSEApp/KgcLogin.html")
    else:
        return render(request, "CPABSEApp/KgcLogin.html")


def cloud_login(request):
    if request.method == "POST":
        uname = request.POST['userid']
        pwd = request.POST['pass']
        askQuery = CloudServer.objects.all().filter(Name=uname, Pass=pwd)
        if askQuery:
            for reg in askQuery:
                name = reg.Name
            request.session['cloud'] = name
            strCloud = request.session['cloud']
            return render(request, "CPABSEApp/CloudHome.html", {"sessionCloud": strCloud, "askQuery": askQuery})
        else:
            messages.success(request, "Invalid User Name and Password")
        return render(request, "CPABSEApp/WrongLogin.html")
    else:
        if 'cloud' in request.session:
            strCloud = request.session['cloud']
            askQuery = CloudServer.objects.all().filter(Name=strCloud)
            if askQuery:
                return render(request, "CPABSEApp/CloudHome.html", {"sessionCloud": strCloud, "askQuery": askQuery})
        else:
            return render(request, "CPABSEApp/CloudLogin.html")


def cloud_home(request):
    if 'cloud' in request.session:
        strCloud = request.session['cloud']
        askQuery = CloudServer.objects.all().filter(Name=strCloud)
        if askQuery:
            return render(request, "CPABSEApp/CloudHome.html", {"sessionCloud": strCloud, "askQuery": askQuery})
        else:
            return render(request, "CPABSEApp/CloudHome.html", {"sessionCloud": strCloud})
    else:
        return render(request, "CPABSEApp/CloudLogin.html")


def cloud_view_iot_dvice(request):
    if 'cloud' in request.session:
        strCloud = request.session['cloud']
        askQuery = IoTDevices.objects.all().order_by('id')
        if askQuery:
            return render(request, "CPABSEApp/CloudViewIoTDevice.html", {"sessionCloud": strCloud, "askQuery": askQuery})
        else:
            return render(request, "CPABSEApp/CloudViewIoTDevice.html", {"sessionCloud": strCloud})
    else:
        return render(request, "CPABSEApp/CloudLogin.html")


def cloud_view_owners(request):
    if 'cloud' in request.session:
        strCloud = request.session['cloud']
        askQuery = OwnerRegistration.objects.all().order_by('id')
        if askQuery:
            return render(request, "CPABSEApp/CloudViewOwners.html", {"sessionCloud": strCloud, "askQuery": askQuery})
        else:
            return render(request, "CPABSEApp/CloudViewOwners.html", {"sessionCloud": strCloud})
    else:
        return render(request, "CPABSEApp/CloudLogin.html")


def cloud_owner_files(request):
    if 'cloud' in request.session:
        strCloud = request.session['cloud']
        askQuery = DataStorage.objects.all().filter(FStatus = "Original").order_by('id')
        if askQuery:
            return render(request, "CPABSEApp/CloudOwnerFiles.html", {"sessionCloud": strCloud, "askQuery": askQuery})
        else:
            return render(request, "CPABSEApp/CloudOwnerFiles.html", {"sessionCloud": strCloud})
    else:
        return render(request, "CPABSEApp/CloudLogin.html")


def cloud_viewed_file(request, filename):
    if 'cloud' in request.session:
        strCloud = request.session['cloud']
        askQuery = DataStorage.objects.all().filter(FileName=filename).order_by('id')
        if askQuery:
            return render(request, "CPABSEApp/CloudViewedFile.html", {"sessionCloud": strCloud, "askQuery": askQuery})
        else:
            return render(request, "CPABSEApp/CloudOwnerFiles.html", {"sessionCloud": strCloud})
    else:
        return render(request, "CPABSEApp/CloudLogin.html")


def cloud_logout(request):
    if 'cloud' in request.session:
        del request.session['cloud']
        for key in list(request.session.keys()):
            del request.session[key]
        messages.success(request, "Logged Out Successfully.")
        return render(request, "CPABSEApp/CloudLogin.html")
    else:
        return render(request, "CPABSEApp/CloudLogin.html")


def address_creation():
    n = random.random()
    addr = str(n) + "abacs"
    result = hashlib.sha1(addr.encode())
    return result.hexdigest()


def privatekey_generate():
    password = "s3cr3t*c0d3"
    passwordSalt = os.urandom(8)
    key = pbkdf2.PBKDF2(password, passwordSalt).read(8)
    return str(binascii.hexlify(key),'utf-8')


def trapdoor_generate():
    secretKey = os.urandom(8)
    return str(binascii.hexlify(secretKey),'utf-8')


def encrypt(plain_text, password):
    # generate a random salt
    salt = get_random_bytes(AES.block_size)
    # use the Scrypt KDF to get a private key from the password
    private_key = hashlib.scrypt(
        password.encode(), salt=salt, n=2 ** 14, r=8, p=1, dklen=32)
    # create cipher config
    cipher_config = AES.new(private_key, AES.MODE_GCM)
    # return a dictionary with the encrypted text
    cipher_text, tag = cipher_config.encrypt_and_digest(bytes(plain_text, 'utf-8'))
    return {
        'cipher_text': b64encode(cipher_text).decode('utf-8'),
        'salt': b64encode(salt).decode('utf-8'),
        'nonce': b64encode(cipher_config.nonce).decode('utf-8'),
        'tag': b64encode(tag).decode('utf-8')
    }


def decrypt(enc_dict, password):
    # decode the dictionary entries from base64
    salt = b64decode(enc_dict['salt'])
    cipher_text = b64decode(enc_dict['cipher_text'])
    nonce = b64decode(enc_dict['nonce'])
    tag = b64decode(enc_dict['tag'])
    # generate the private key from the password and salt
    private_key = hashlib.scrypt(
        password.encode(), salt=salt, n=2 ** 14, r=8, p=1, dklen=32)
    # create the cipher config
    cipher = AES.new(private_key, AES.MODE_GCM, nonce=nonce)
    # decrypt the cipher text
    decrypted = cipher.decrypt_and_verify(cipher_text, tag)

    return decrypted

