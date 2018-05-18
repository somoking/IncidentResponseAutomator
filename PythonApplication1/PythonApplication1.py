import co3
import json
import _ldap as ldap
import sys
import splunklib
from splunklib import client,results
import ConfigParser
import os.path
from os.path import dirname
import asyncore
import re
from sets import ImmutableSet
import string
import time
from datetime import datetime  
from datetime import timedelta  
import pprint


class Artifact:
    def __init__(self,IncidentID=None,Type=None,Value=None,Description=None,Created=None):
        self.IncidentID = IncidentID
        self.Type = Type
        self.Value = Value
        self.Description = Description
        self.Created = Created
        
    def __eq__ (self, other):
        SelfTemp= dict(self.__dict__)
        del SelfTemp["Description"]
        del SelfTemp["Created"]
        OtherTemp= dict(other.__dict__)
        del OtherTemp["Description"]
        del OtherTemp["Created"]
        return SelfTemp == OtherTemp

    def __hash__(self):
        return hash((self.IncidentID,self.Type,self.Value))

# Resiliant Section ===========================================================
class ResiliantDictionary:
    def __init__(self,ResiliantClient):
        self.ResiliantClient = ResiliantClient
        self.conf=ResiliantClient.get_const()

    def ArtifactNameToID(self, Name):
        for ArtifactType in self.conf["artifact_types"]:
            if ArtifactType["name"]==Name:
                return ArtifactType["id"]
        return Name

def GetOpenArtifacts(ResiliantClient):
    OpenIncidents = ResiliantClient.get("/incidents/open")
    NewArtifacts = []
    LastObject = 0
    for OpenIncident in OpenIncidents:
        if LastObject<OpenIncident["create_date"]:
            LastObject=OpenIncident["create_date"]
        IncidentID=OpenIncident["id"]
        IncidentDate=OpenIncident["discovered_date"]
        IncidentArtifacts = ResiliantClient.get("/incidents/"+str(IncidentID)+"/artifacts")
        for IncidentArtifact in IncidentArtifacts:
            if LastObject<IncidentArtifact["created"]:
                LastObject=IncidentArtifact["created"]
            NewArtifact = Artifact(IncidentID
                                   ,IncidentArtifact["type"]
                                   ,(IncidentArtifact["value"]).lower()
                                   ,IncidentArtifact["description"]
                                   ,IncidentDate)

            NewArtifacts.append(NewArtifact)
    return (NewArtifacts,LastObject)

def GetNewArtifacts(ResiliantClient,Dictionary=None,**QueryParameters):
    LastObject = 0
    GetString="/newsfeed"
    if len(QueryParameters)!=0:
        GetString +="?"
        for ParamKey in QueryParameters:
            GetString += ParamKey+ "="+ QueryParameters[ParamKey]+"&"
        GetString=GetString[:(len(GetString)-1)]
    OpenIncidents = ResiliantClient.get(GetString)
    NewArtifacts = []
    for OpenIncident in OpenIncidents:
        if LastObject<OpenIncident["after"]["created"]:
                LastObject=OpenIncident["after"]["created"]
                Type=OpenIncident["after"]["type"]
                if(Dictionary!=None):
                    Type=ResiliantDict.ArtifactNameToID(Type)
        NewArtifacts.append(Artifact(OpenIncident["after"]["inc_id"]
                                     ,Type
                                     ,(OpenIncident["after"]["value"]).lower()
                                     ,OpenIncident["after"]["description"]
                                     ,OpenIncident["timestamp"]))
    return (NewArtifacts,LastObject)

def SetArtifact(ResiliantClient,Artifact):
    PostDict={"type" : {"id" : Artifact.Type}
              ,"value" : Artifact.Value
              , "description" : { "format" : "text", "content" : Artifact.Description}
              ,"attachment" : None
              ,"perms" : {"read" : True,"write" : True,"delete" : True}
              , "properties" : None
              , "relating" : None
              ,"parent_id": None}
    PostString="/incidents/"+str(Artifact.IncidentID)+"/artifacts"
    #OpenIncidents = ResiliantClient.post(PostString,PostDict)

def SetNewArtifacts(ResiliantClient,Artifacts):
    print "Populating Data into Resilant"
    Time1=datetime.now()
    IncidentIDs = []
    TestArtifacts = []
    for artifact in Artifacts:
        IncidentIDs.append(artifact.IncidentID)
    for Incident in set(IncidentIDs):
        IncidentArtifacts = ResiliantClient.get("/incidents/"+str(artifact.IncidentID)+"/artifacts")
        for IncidentArtifact in IncidentArtifacts:
            TestArtifacts.append(Artifact(artifact.IncidentID
                                         ,IncidentArtifact["type"]
                                         ,(IncidentArtifact["value"]).lower()
                                         ,IncidentArtifact["description"]))
    Diffrenceset=set(TestArtifacts)
    Artifacts=set(Artifacts)
    FinalArtifacts=Artifacts - Diffrenceset
    for artifact in FinalArtifacts:
        #SetArtifact(ResiliantClient,artifact)
        print artifact.IncidentID,artifact.Type,artifact.Value,artifact.Description
    Time2=datetime.now()
    print "Data Populated into Resilant | ",(Time2-Time1).total_seconds()," Seconds elaspsed"

# Ldap Section =================================================================
def LDAPBind(binddn,password):
     LDAPobject = ldap.initialize('LDAP://molina.mhc:389')
     try:
        LDAPobject.set_option(ldap.OPT_REFERRALS, 0)
        LDAPobject.simple_bind(binddn,password)
        LDAPobject.result4()
     except ldap.INVALID_CREDENTIALS:
        print "Error connecting to LDAP: Your username or password is incorrect."
        raw_input("Program will now exit")
        sys.exit(0)
     except ldap.LDAPError, e:
        if type(e.message) == dict and e.message.has_key('desc'):
            print e.message['desc']
        else: 
            print e
     return LDAPobject

def LDAPSearch(LDAPobject,searchValue,returnAttribute):
     basedn = "DC=molina,DC=mhc"
     searchFilter = searchValue
     searchAttribute = returnAttribute #["samaccountname"]
     searchScope =ldap.SCOPE_SUBTREE
     try:    
        ldap_result_id = LDAPobject.search_ext(basedn,searchScope,searchFilter,searchAttribute)
        while 1:
            Returnvalue= LDAPobject.result4(ldap_result_id, 0)
            return Returnvalue
     except ldap.LDAPError, e:
        print e

def GetSameAccountName(LDAPObject,Artifacts):

    EmailArtifacts = list(filter(lambda x: (x.Type==9 or x.Type==20) and
                                 re.search("@molinahealthcare",x.Value,re.IGNORECASE)!=None
                                 ,Artifacts))
    NewArtifacts=[]
    returnAttribute=["samaccountname"]
    for EmailArtifact in EmailArtifacts:
        searchValue="mail="+ EmailArtifact.Value
        LDAPValue =LDAPSearch(LDAPObject,searchValue,returnAttribute)
        UserAccount=(LDAPValue[1][0][1]["sAMAccountName"][0]).lower()
        Description= UserAccount +" was populated from " +EmailArtifact.Value+" using LDAP"
        NewArtifacts.append(Artifact(EmailArtifact.IncidentID,23,UserAccount,Description,EmailArtifact.Created))
    return NewArtifacts

#Splunk Section ===============================================================
def SplunkSearch(SplunkClient,QueryParams,SearchArgs,head):
    SearchQuery="search "
    for key in QueryParams:
        SearchQuery+=key + "=" + QueryParams[key]+" "
    SearchQuery+="| head "+str(head)
    
    job=SplunkClient.search(SearchQuery,**SearchArgs)
    sid= job["sid"]
    resultlist=[]
    for result in results.ResultsReader(job.results()):#change to return a list if head is >1
        resultlist.append(result)
    job=SplunkClient.job(sid)
    job.set_ttl(10)
    return resultlist
  
def GetIPAddress(SplunkClient,UsertoIPArtifacts):
    NewIPArtifacts=[]
    for artifact in UsertoIPArtifacts:
        User=string.replace(artifact.Value, "mmc\\","")
        Datetime=datetime.fromtimestamp((artifact.Created/1000))

        offset = time.timezone if (time.localtime().tm_isdst == 0) else time.altzone
        offset =str(offset/60/60*-1)+":00"
        earliest_time=(Datetime-timedelta(minutes=40)).strftime('%Y-%m-%dT%H:%M:%S.000')+offset
        latest_time=(Datetime).strftime('%Y-%m-%dT%H:%M:%S.000')+offset
        SearchArgs = {"earliest_time":earliest_time#"2018-01-03T09:00:00.000-08:00",
                      ,"latest_time": latest_time#"2018-01-23T12:00:00.000-07:00",
                      ,"exec_mode": "blocking"}
        QueryParams={"source":'"WinEventLog:Security"'
                    ,"sourcetype":'"WinEventLog:Security"'
                    ,"SourceName":'"Microsoft Windows security auditing."'
                    ,"user":User
                    ,"EventCode":"4624"
                    ,"src_ip":'"10*"'}
        SplunkResult=SplunkSearch(SplunkClient,QueryParams,SearchArgs,1)
        if SplunkResult!=[] and SplunkResult[0]["src_ip"] is not None:
            Description= SplunkResult[0]["src_ip"] +" was populated from " +User+" using Splunk"
            NewIPArtifacts.append(Artifact(artifact.IncidentID,1,SplunkResult[0]["src_ip"],Description))
    return NewIPArtifacts

def GetComputerNames(SplunkClient,UsertoIPArtifacts):
    NewIPArtifacts=[]
    for artifact in UsertoIPArtifacts:
        User=string.replace(artifact.Value, "mmc\\","")
        Datetime=datetime.fromtimestamp((artifact.Created/1000))

        offset = time.timezone if (time.localtime().tm_isdst == 0) else time.altzone
        offset =str(offset/60/60*-1)+":00"
        earliest_time=(Datetime-timedelta(minutes=130)).strftime('%Y-%m-%dT%H:%M:%S.000')+offset
        latest_time=(Datetime).strftime('%Y-%m-%dT%H:%M:%S.000')+offset
        SearchArgs = {"earliest_time":earliest_time#"2018-01-03T09:00:00.000-08:00",
                      ,"latest_time": latest_time#"2018-01-23T12:00:00.000-07:00",
                      ,"exec_mode": "blocking"}
        QueryParams={"source":'"WinEventLog:Security"'
                    ,"sourcetype":'"WinEventLog:Security"'
                    ,"user":User
                    ,"Authentication_Package":"NTLM"
                    ,"src_ip":'"172*"'}
        SplunkResult=SplunkSearch(SplunkClient,QueryParams,SearchArgs,1)
        if SplunkResult!=[] and SplunkResult[0]["Workstation_Name"] is not None:
            Description= SplunkResult[0]["Workstation_Name"] +" was populated from " +User+" using Splunk"
            NewIPArtifacts.append(Artifact(artifact.IncidentID,25,SplunkResult[0]["Workstation_Name"],Description))
    return NewIPArtifacts

#Contains all Artifact populators
def NewArtifactPopulator(SplunkClient,LDAPObject,OpenArtifacts):

    print "Data Creation Start -----"
    Time1=datetime.now()
    print "Data Creation Username"
    NewUserArtifacts=set(GetSameAccountName(LDAPObject,OpenArtifacts))
    Time2=datetime.now()
    print "End Username | ",(Time2-Time1).total_seconds()," Seconds elaspsed"

    OldUserArtifacts=set(filter(lambda x: (x.Type==23)and(x.Value!="system"),OpenArtifacts))
    UserArtifactsforSplunk=NewUserArtifacts-OldUserArtifacts | OldUserArtifacts

    Time1=datetime.now()
    print "Data Creation ComputerName"
    NewComputerNameArtifacts=set(GetComputerNames(SplunkClient,UserArtifactsforSplunk))
    Time2=datetime.now()
    print "End ComputerName | ",(Time2-Time1).total_seconds()," Seconds elaspsed"


    Time1=datetime.now()
    print "Data Creation IP Address"
    NewIPArtifacts=set(GetIPAddress(SplunkClient,UserArtifactsforSplunk))
    Time2=datetime.now()
    print "End IP Address | ",(Time2-Time1).total_seconds()," Seconds elaspsed"


    print "Data Creation End -----"
    return (NewIPArtifacts|NewComputerNameArtifacts|NewUserArtifacts)

#==================================MAIN=======================================

print "Start Init" 
Time1=datetime.now()

TimeToClose=(datetime.now()+timedelta(hours=1))#+timedelta(days=1))
Filepath = "C:\Users\sanlesso\Documents\Visual Studio 2015\Projects\PythonApplication1\PythonConfig.ini"
Config=ConfigParser.SafeConfigParser()
Config.read(Filepath)
try:
    ResiliantClient= co3.get_client(
    {
        "email":Config.get("Resiliant", "email"),
        "password":Config.get("Resiliant", "password"),
        "org":Config.get("Resiliant", "org"),
        "org_id":int(Config.get("Resiliant", "org_id")),
        "host":Config.get("Resiliant", "host"),
        "port":int(Config.get("Resiliant", "port")),
        "cafile":"false" # Cafile can be set to true to use a certificate
     })
    print "Resiliant Connected"
except ValueError:
    print "Error connecting to Resiliant: "+ValueError.message
    raw_input("Program will now exit")
    sys.exit(0)
try:
   LDAPObject=LDAPBind(Config.get("LDAP", "binddn"),Config.get("LDAP", "password"))
   print "LDAP Connected"
except ValueError:
    print "Error connecting to LDAP: "+ValueError.message
    raw_input("Program will now exit")
    sys.exit(0)
try:
    SplunkClient=client.connect(
     host=Config.get("Splunk", "host"),
     password=Config.get("Splunk", "password"),
     username=Config.get("Splunk", "username"),autologin=True)
    print "Splunk Connected"
except ValueError:
    print "Error connecting to Splunk: "+ValueError.message
    raw_input("Program will now exit")
    sys.exit(0)

ResiliantDict=ResiliantDictionary(ResiliantClient)

Time2=datetime.now()
print "End Init | ",(Time2-Time1).total_seconds()," Seconds elaspsed"
print "Start Initial Batch"
Time1=datetime.now()
OpenArtifactsData = GetOpenArtifacts(ResiliantClient)
LastObject=OpenArtifactsData[1]
OpenArtifacts=list(filter(lambda x: (x.IncidentID==18978),OpenArtifactsData[0]))#OpenArtifacts=OpenArtifactsData[0]
CreatedArtifacts=NewArtifactPopulator(SplunkClient,LDAPObject,OpenArtifacts)
SetNewArtifacts(ResiliantClient,CreatedArtifacts)
Time2=datetime.now()
print "End Initial Batch | ",(Time2-Time1).total_seconds()," Seconds elaspsed"

# Monitoring Section ==========================================================
print "Start Monitoring Section================================================"
while TimeToClose>datetime.now():
    print "Start Monitoring -----",LastObject
    Time1=datetime.now()
    Finalize=(Time1+timedelta(minutes=2))
    QueryParameters={"entry_type":"CREATE","object_type":"ARTIFACT","since_date":str(LastObject)}
    NewArtifactsData=GetNewArtifacts(ResiliantClient,Dictionary=ResiliantDict,**QueryParameters)
    LastObject=NewArtifactsData[1]
    NewArtifacts=list(filter(lambda x: (x.IncidentID==18978),NewArtifactsData[0]))#NewArtifacts=set(NewArtifactsData[0])
    if NewArtifacts!=[]:
        CreatedArtifacts=NewArtifactPopulator(SplunkClient,LDAPObject,NewArtifacts)
        SetNewArtifacts(ResiliantClient,CreatedArtifacts)
    if Finalize>datetime.now():
        WaitTime=(Finalize-datetime.now()).total_seconds()
        time.sleep(WaitTime)
        Time2=datetime.now()
        print "End Monitoring Batch | ",(Time2-Time1).total_seconds()," Seconds elaspsed"
print "End Monitoring Section================================================"
raw_input("++++++++++++++++End++++++++++++++++++")





#list(filter(lambda x: (x.IncidentID==18978)
#Reusable Object/function Bank
"""
QueryParameters={"entry_type":"CREATE","object_type":"ARTIFACT","since_date":"1514764800000"}
json.loads(response.text)    raw_input()
QueryParams={"source":'"WinEventLog:Security"'
            ,"sourcetype":'"WinEventLog:Security"'
            ,"SourceName":'"Microsoft Windows security auditing."'
            ,"user": "sanleso"
            ,"EventCode":"4624"
            ,"src_ip":'"10*"'}
 #SearchQuery = "search source=\"WinEventLog:Security\" sourcetype=\"WinEventLog:Security\" SourceName=\"Microsoft Windows security auditing.\" user="+ user +"EventCode=4624 src_ip=\"10*\" | head 1 "
  #SearchArgs = {"earliest_time": "2018-01-03T09:00:00.000-08:00","latest_time": "2018-01-03T12:00:00.000-07:00","exec_mode": "blocking"}
 """

