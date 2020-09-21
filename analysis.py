import requests
import json
import time
import perturbation as p
import lief
import random

apikeylist = open("vt_api_key").read().split("\n")[:-1]
apilen = len(apikeylist)

def send_to_sandbox(fname):
    sburl = "http://localhost:8090/tasks/create/file"
    data = {'timeout': '30'}
    with open(fname,'rb') as sample:
        files = {"file": (fname,sample)}
        header = {"Authorization": "Bearer cuckoo"}
        r = requests.post(sburl, data=data, files=files, headers=header)

    if r.status_code == 200:
        return r.json()

    return false

def status(taskid):
    spurl = "http://localhost:8090/tasks/view/"
    data = {'timeout': '30'}
    header = {"Authorization": "Bearer cuckoo"}

    r = requests.get(spurl+str(taskid), headers=header)
    return r.json()

def get_cuckoo_report(fname):
    rpurl = "http://localhost:8090/tasks/report/"
    data = {'timeout': '30'}
    header = {"Authorization": "Bearer cuckoo"}

    taskid = send_to_sandbox(fname)["task_id"]

    while status(taskid)['task']['status'] != "reported":
        time.sleep(10)

    r = requests.get(rpurl+str(taskid), headers=header)
    return r.json()

def send_vt_scan(fpath, apikey):
    url = 'https://www.virustotal.com/vtapi/v2/file/scan'
    params = {'apikey': apikey}
    files = {'file': ('myfile.exe', open(fpath, 'rb'))}
    response = requests.post(url, files=files, params=params)
    return response.json()["md5"]
    # pass

def get_vt_report(hashvalue,apikey):
    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    params = {'apikey': apikey, 'resource': hashvalue}
    response = requests.get(url, params=params)
    # status = response.json()["response_code"]
    
    return response.json()

def vt_analysis(filehash):
    random.seed(None)
    i = random.randrange(0,apilen)
    # print (apikeylist[i])
    #scan = send_vt_scan(fpath,apikeylist[i])
    #filehash = scan["md5"]
    while True:
        i = (i+1)%apilen
        vt_report = get_vt_report(filehash, apikeylist[i])
        if vt_report["response_code"] == 1:
            vt_result = vt_report["positives"]/vt_report["total"]
            break
        time.sleep(10)

    return vt_result, vt_report

def check_sig_set(signatures):
    sigs = []
    for sig in signatures:
        
        if sig["severity"] > 1:
            sigs.append(sig["description"])

    return set(sigs)

def check_key_instructions():
    pass

# origin = json report, target = filename
def func_check(origin_sig,target):
    target_sig = get_cuckoo_report(target)["signatures"]
    
    osig = check_sig_set(origin_sig)
    tsig = check_sig_set(target_sig)

    total = osig | tsig
    match = osig & tsig

    if len(match)/len(total) > 0.6:
        return True
    else:
        return False

