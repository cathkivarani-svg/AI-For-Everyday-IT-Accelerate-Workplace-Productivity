from django.db import models


# Create your models here.
class OwnerRegistration(models.Model):
    UserName = models.CharField(max_length=100)
    Pwd = models.CharField(max_length=100)
    Name = models.CharField(max_length=100)
    Gender = models.CharField(max_length=50)
    Dob = models.DateTimeField(blank=True, null=True)
    Email = models.EmailField()
    MobileNo = models.CharField(max_length=50)
    Address = models.CharField(max_length=500)
    PinCode = models.CharField(max_length=50)
    OwnerType = models.CharField(max_length=100)
    ProfileImg = models.CharField(max_length=500)
    AuthorizeKey = models.CharField(max_length=100)
    Status = models.CharField(max_length=50)

    class Meta:
        db_table = "OwnerRegistration"


class IoTDevices(models.Model):
    UserName = models.CharField(max_length=100)
    Pwd = models.CharField(max_length=100)
    Name = models.CharField(max_length=100)
    Email = models.EmailField()
    Address = models.CharField(max_length=500)
    PinCode = models.CharField(max_length=50)
    DeviceType = models.CharField(max_length=100)
    ProfileImg = models.CharField(max_length=500)
    AuthorizeKey = models.CharField(max_length=100)
    Status = models.CharField(max_length=50)

    class Meta:
        db_table = "IoTDevices"


class Transaction(models.Model):
    Owner = models.CharField(max_length=50)
    FileName = models.CharField(max_length=100)
    Task = models.CharField(max_length=100)
    TDate = models.DateTimeField(blank=True, null=True)

    class Meta:
        db_table = "Transaction"


class KGC(models.Model):
    Name = models.CharField(max_length=100)
    Pass = models.CharField(max_length=100)

    class Meta:
        db_table = "KGC"


class CloudServer(models.Model):
    Name = models.CharField(max_length=100)
    Pass = models.CharField(max_length=100)

    class Meta:
        db_table = "CloudServer"


class Search(models.Model):
    Owner = models.CharField(max_length=100)
    Keyword = models.CharField(max_length=100)
    SDate = models.DateTimeField(blank=True, null=True)

    class Meta:
        db_table = "Search"


class KeyRequest(models.Model):
    Owner = models.CharField(max_length=100)
    IoTDevice = models.CharField(max_length=100)
    FileName = models.CharField(max_length=100)
    PrivateKey = models.CharField(max_length=100)
    Trapdoor = models.CharField(max_length=100)
    PublicKey = models.CharField(max_length=100, null=True)

    class Meta:
        db_table = "KeyRequest"


class IoTDeviceFiles(models.Model):
    FileName = models.CharField(max_length=100)
    IoTDevice = models.CharField(max_length=100)
    FileContent = models.CharField(max_length=5000)
    Keyword = models.CharField(max_length=200)
    PublicKey = models.CharField(max_length=100, null=True)
    UDate = models.DateTimeField(blank=True, null=True)

    class Meta:
        db_table = "IoTDeviceFiles"


class DataStorage(models.Model):
    FileName = models.CharField(max_length=100)
    FileContent = models.CharField(max_length=5000)
    Keyword = models.CharField(max_length=200)
    PublicKey = models.CharField(max_length=100, null=True)
    Ranks = models.IntegerField(blank=True, null=True)
    UDate = models.CharField(max_length=5000)
    IoTDevice = models.CharField(max_length=100)
    FStatus = models.CharField(max_length=50)

    class Meta:
        db_table = "DataStorage"


class IOTKeys(models.Model):
    IoTDevice = models.CharField(max_length=100)
    FileName = models.CharField(max_length=100)
    D1PublicKey = models.CharField(max_length=100)
    D1PrivateKey = models.CharField(max_length=100)
    D1Trapdoor = models.CharField(max_length=100)
    D1Keyword = models.CharField(max_length=500)
    D2PublicKey = models.CharField(max_length=100)
    D2PrivateKey = models.CharField(max_length=100)
    D2Trapdoor = models.CharField(max_length=100)
    D2Keyword = models.CharField(max_length=500)
    KeyStatus = models.CharField(max_length=100)

    class Meta:
        db_table = "IOTKeys"


class Attacker(models.Model):
    Owner = models.CharField(max_length=100)
    FileName = models.CharField(max_length=100)
    AttackKey = models.CharField(max_length=100)
    ADate = models.DateTimeField(blank=True, null=True)
    AttackType = models.CharField(max_length=50)

    class Meta:
        db_table = "Attacker"

