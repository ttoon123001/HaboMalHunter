#!/usr/bin/python
#encoding: utf-8
#Version 1.0.0.1

"""
Tencent is pleased to support the open source community by making HaboMalHunter available.
Copyright (C) 2017 THL A29 Limited, a Tencent company. All rights reserved.
Licensed under the MIT License (the "License"); you may not use this file except in 
compliance with the License. You may obtain a copy of the License at

http://opensource.org/licenses/MIT

Unless required by applicable law or agreed to in writing, software distributed under the 
License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, 
either express or implied. See the License for the specific language governing permissions 
and limitations under the License.
"""
import os 
import sys
import json
import subprocess






def classifyLogInfo(dynamicLog):
    main_proc = 0

    sampleName = ""
    infoDict = {"subproc": [], "proc":{}, "file": {}, "net": {}, "hash": {}} #
    
     #, "Other":{}
    connected = {}
    procList = []   #execve ->
    subprocList = []
    
    outJson = []

    xpcn = "%s/output.xpcn" % os.path.dirname(dynamicLog)
    static = "%s/output.static" % os.path.dirname(dynamicLog)

    if os.path.exists(static):
        f = open(static,"r")
        StContent = f.read()
        f.close()

    if os.path.exists(dynamicLog):
        f = open(dynamicLog, "r")
        dyContent = f.read()
        f.close()

        stJson = json.loads(StContent)
        dyJson = json.loads(dyContent)
        
        procPid = 0

        for item in dyJson:
            try:
                src = item[1]
                detail = item[2]
                dyID = int(item[3])
                desript = item[4]

                if dyID in (8020005, 8020006, 8020007, 8020008,  8020010, 8020011, 8020012, 8020200): #8020009,
                    if dyID == 8020005:     #clone系统调用
                        # procinfo = {}
                        # procinfo["path"] = src.split("(")[0]
                        # procinfo["spid"] = detail.split("=")[1][0:-1]
                        #
                        # ProcNum = src.split("(")[1].split(",")[0].split("=")[1]
                        #
                        # #样本产生的有效PID
                        # idx = procList.index(ProcNum)
                        # if outJson[idx]["proc"].has_key(desript):
                        #     outJson[idx]["proc"][desript].append(procinfo)
                        # else:
                        #     outJson[idx]["proc"][desript] = [procinfo]
                        pass

                    if dyID == 8020010:     #fork创建进程
                        procinfo = {}
                        ProcNum = detail.split("=")[1][0:-1]
                        ls_src = src.split('(')
                        Procpath = ls_src[0]
                        ppid = ls_src[1].split(',')[0]
                        ppid = ppid.split('=')[1]

                        if not procList.count(ProcNum):
                            procList.append(ProcNum)
                        else:
                            continue

                        dtInfo = {"proc": {}, "file": {}, "net": {}, "hash": {}}
                        dtInfo["ppid"] = ppid
                        dtInfo["pid"] = ProcNum
                        dtInfo["path"] = Procpath
                        dtInfo["command"] = detail.split(':')[1]

                        try:
                            if Procpath[0] == ' ':
                                temp = list(Procpath)
                                temp[0] = '/'
                                Procpath = ''.join(temp)
                                pass

                            Procpath = Procpath.rstrip()

                            if os.path.exists(Procpath):
                                md5 = subprocess.check_output(['/usr/bin/md5sum', '-b', Procpath])
                                sha1 = subprocess.check_output(['/usr/bin/sha1sum', '-b', Procpath])
                                sha256 = subprocess.check_output(['/usr/bin/sha256sum', '-b', Procpath])
                                md5 = md5.split(' ')[0]
                                sha1 = sha1.split(' ')[0]
                                sha256 = sha256.split(' ')[0]

                                dtInfo["hash"]["md5"] = md5
                                dtInfo["hash"]["sha1"] = sha1
                                dtInfo["hash"]["sha256"] = sha256
                        except subprocess.CalledProcessError as e:
                            print("calledProcessError:%s" % e)

                        if procList.count(ProcNum):
                            infoDict["subproc"].append(dtInfo)

                        pass


                    if dyID == 8020006:     #execve装载新程序
                        procinfo = {}
                        ProcNum = src.split("(")[1].split(",")[0].split("=")[1]
                        Procpath = src.split('(')[0]

                        if not procList.count(ProcNum):
                            procList.append(ProcNum)

                        #第一个进程作为主进程
                        if main_proc == 0:
                            main_proc = ProcNum

                            infoDict["pid"] = ProcNum
                            infoDict["path"] = Procpath
                            infoDict["command"] = detail.split(':')[1]
                            infoDict["load"] = []

                            infoDict["hash"]["md5"] = stJson["BaseInfo"][0]["MD5"]
                            infoDict["hash"]["sha1"] = stJson["BaseInfo"][0]["SHA1"]
                            infoDict["hash"]["sha25"] = stJson["BaseInfo"][0]["SHA256"]
                        #只加载，不创建进程
                        elif main_proc == ProcNum:
                            infoDict["laod"].append(Procpath)
                        #加载同时创建进程(缺少显示ppid)
                        else:
                            dtInfo = {"proc": {}, "file": {}, "net": {}, "hash": {}}

                            dtInfo["pid"] = ProcNum
                            dtInfo["path"] = Procpath
                            dtInfo["command"] = detail.split(':')[1]

                            try:
                                if Procpath[0] == ' ':
                                    temp = list(Procpath)
                                    temp[0] = '/'
                                    Procpath = ''.join(temp)
                                    pass

                                if os.path.exists(Procpath):
                                    md5 = subprocess.check_output(['/usr/bin/md5sum', '-b', Procpath])
                                    sha1 = subprocess.check_output(['/usr/bin/sha1sum', '-b', Procpath])
                                    sha256 = subprocess.check_output(['/usr/bin/sha256sum', '-b', Procpath])
                                    md5 = md5.split(' ')[0]
                                    sha1 = sha1.split(' ')[0]
                                    sha256 = sha256.split(' ')[0]

                                    dtInfo["hash"]["md5"] = md5
                                    dtInfo["hash"]["sha1"] = sha1
                                    dtInfo["hash"]["sha256"] = sha256
                            except subprocess.CalledProcessError as e:
                                print("calledProcessError:%s" % e)

                            if procList.count(ProcNum):
                                infoDict["subproc"].append(dtInfo)

                            #outJson.append(infoDict1)

                    if dyID == 8020200:
                        procinfo = {}

                        pid = src.split(' ')[1]
                        if detail.count('<'):
                            detail = detail.split('<')[0]
                        procinfo["dpid"] = unicode(str(int(detail.split(',')[0], 16)),"utf-8")
                        flag = procinfo["flag"] = detail.split(',')[1]

                        if -1 == flag.find('0x9') and -1 == flag.find('0xf'):
                            continue

                        idx = procList.index(pid)
                        if main_proc == pid:
                            if infoDict["proc"].has_key(desript):
                                infoDict["proc"][desript].append(procinfo)
                            else:
                                infoDict["proc"][desript] = [procinfo]
                        else:
                            if 0 < len(infoDict["subproc"]):
                                for dt in infoDict["subproc"]:
                                    if dt["pid"] != pid:
                                        continue
                                    if dt["proc"].has_key(desript):
                                        dt["proc"][desript].append(procinfo)
                                    else:
                                        dt["proc"][desript] = [procinfo]

                        pass


                elif dyID in (8020201, 8020202, 8020203, 8020204, 8020205, 8020206, 8020210): #, 8020212(self lock)
                    files = {}
                    pid = src.split("(")[1].split(",")[0].split("=")[1]
                    files["path"] = detail.split(",")[0].split("=")[1]

                    if dyID == 8020201:
                        files["param"] = detail.split(",")[1].split("=")[1]
                    else:
                        files["size"] = detail.split(",")[1].split("=")[1]
                    idx = procList.index(pid)
                    if main_proc == pid:
                        if infoDict["file"].has_key(desript):
                            infoDict["file"][desript].append(files)
                        else:
                            infoDict["file"][desript] = [files]
                    else:
                        if 0 < len(infoDict["subproc"]):
                            for dt in infoDict["subproc"]:
                                if dt["pid"] != pid:
                                    continue
                                if dt["file"].has_key(desript):
                                    dt["file"][desript].append(files)
                                else:
                                    dt["file"][desript] = [files]
                    # if outJson[idx]["file"].has_key(desript):
                    #     outJson[idx]["file"][desript].append(files)
                    # else:
                    #     outJson[idx]["file"][desript] = [files]
                        pass

                elif dyID in (8020401, 8020402, 8020403, 8020405, 8020406, 8020408, 8020409, 8020410, 8020411, 8020414): #8020407, 8020404
                    if dyID == 8020401:
                        socket = {}
                        socket["param"] = detail.split(":")[1]
                        pid = src.split("(")[1].split(",")[0].split("=")[1]

                        idx = procList.index(pid)
                        if main_proc == pid:
                            if infoDict["net"].has_key(desript):
                                infoDict["net"][desript].append(socket)
                            else:
                                infoDict["net"][desript] = [socket]
                        else:
                            if 0 < len(infoDict["subproc"]):
                                for dt in infoDict["subproc"]:
                                    if dt["pid"] != pid:
                                        continue
                                    if dt["net"].has_key(desript):
                                        dt["net"][desript].append(socket)
                                    else:
                                        dt["net"][desript] = [socket]


                        # if outJson[idx]["net"].has_key(desript):
                        #     outJson[idx]["net"][desript].append(socket)
                        # else:
                        #     outJson[idx]["net"][desript] = [socket]

                    elif dyID == 8020402:
                        Nets = {}
                        pid = src.split("(")[1].split(",")[0].split("=")[1]
                        data = detail.split("->")
                        Nets["src"] = data[0].split(":")[1]
                        Nets["sport"] = data[0].split(":")[2]
                        Nets["dst"] = data[1].split(":")[0]
                        Nets["dport"] = data[1].split(":")[1]
                        # ProcNum = Nets["pid"]
                        ProcNum = src.split("(")[1].split(",")[0].split("=")[1]

                        # in DNS Qry List
                        connected[Nets["src"].lstrip() + ',' + Nets["dst"] + ' ' + Nets["sport"] + ',' + Nets["dport"]] = ProcNum
                        #connected

                        idx = procList.index(pid)
                        if main_proc == pid:
                            if infoDict["net"].has_key(desript):
                                infoDict["net"][desript].append(Nets)
                            else:
                                infoDict["net"][desript] = [Nets]
                        else:
                            if 0 < len(infoDict["subproc"]):
                                for dt in infoDict["subproc"]:
                                    if dt["pid"] != pid:
                                        continue
                                    if dt["net"].has_key(desript):
                                        dt["net"][desript].append(Nets)
                                    else:
                                        dt["net"][desript] = [Nets]

                    elif dyID == 8020403:
                        procPid = 0
                        # Nets = {"dns": {}}
                        Nets = detail
                        #Nets[""]
                        if connected.has_key(src):
                            procPid = connected[src]
                            pid = procPid

                            idx = procList.index(pid)
                            if main_proc == pid:
                                if infoDict["net"].has_key(desript):
                                    infoDict["net"][desript].append(Nets)
                                else:
                                    infoDict["net"][desript] = [Nets]
                            else:
                                if 0 < len(infoDict["subproc"]):
                                    for dt in infoDict["subproc"]:
                                        if dt["pid"] != pid:
                                            continue
                                        if dt["net"].has_key(desript):
                                            dt["net"][desript].append(Nets)
                                        else:
                                            dt["net"][desript] = [Nets]
                            # if outJson[idx]["net"].has_key(desript):
                            #     outJson[idx]["net"][desript].append(Nets)
                            # else:
                            #     outJson[idx]["net"][desript] = [Nets]
                    elif dyID == 8020411:
                        Nets = {}
                        pid = src.split("(")[1].split(",")[0].split("=")[1]
                        Nets["dst"] = detail.split('->')[1].split(':')[0]
                        Nets["dport"] = detail.split('->')[1].split(':')[1].split(' ')[0]
                        Nets["len"] = detail.split('->')[1].split(':')[1].split(' ')[1]

                        idx = procList.index(pid)
                        if main_proc == pid:
                            if infoDict["net"].has_key(desript):
                                infoDict["net"][desript].append(Nets)
                            else:
                                infoDict["net"][desript] = [Nets]
                        else:
                            if 0 < len(infoDict["subproc"]):
                                for dt in infoDict["subproc"]:
                                    if dt["pid"] != pid:
                                        continue
                                    if dt["net"].has_key(desript):
                                        dt["net"][desript].append(Nets)
                                    else:
                                        dt["net"][desript] = [Nets]
                        # if outJson[idx]["net"].has_key(desript):
                        #     outJson[idx]["net"][desript].append(Nets)
                        # else:
                        #     outJson[idx]["net"][desript] = [Nets]
                        pass
                    else:
                        pass
                        #outJson[idx]["net"][desript] = [detail]
            except Exception as e:
                print(e)

        for name in ["file","net","proc"]:
            for key in infoDict[name]:
                if type(infoDict[name][key] == list):
                    infoDict[name][key] = list(set(str(item) for item in infoDict[name][key]))

            if 0 < len(infoDict["subproc"]):
                for dt in infoDict["subproc"]:
                    for key in dt[name]:
                        if type(dt[name][key] == list):
                            dt[name][key] = list(set(str(item) for item in dt[name][key]))


        #for key in infoDict["proc"]


        # for idx in range(0,len(procList)-1):
        #     for key in outJson[idx]["proc"]:
        #         if type(outJson[idx]["proc"][key][0]) == dict:
        #             immutable_dict = set([str(item) for item in outJson[idx]["proc"][key]])
        #             data = [eval(i) for i in immutable_dict]
        #             outJson[idx]["proc"][key] = data
        #         else:
        #             outJson[idx]["proc"][key] = list(set(outJson[idx]["proc"][key]))

            #infoDict["Dynamic"]["Process"][key] = list(set(infoDict["Dynamic"]["Process"][key]))#[0:15]

        # 1 去重 2 长数据截断为15字节的列表
        # for idx in range(0,len(procList)-1):
        #     for key in outJson[idx]["file"]:
        #         if type(outJson[idx]["file"][key][0]) == dict:
        #             immutable_dict = set([str(item) for item in outJson[idx]["file"][key]])
        #             data = [eval(i) for i in immutable_dict]
        #             outJson[idx]["file"][key] = data
        #         else:
        #             outJson[idx]["file"][key] = list(set(outJson[idx]["file"][key]))


            # infoDict["Dynamic"]["File"][key] = list(set(infoDict["Dynamic"]["File"][key]))#[0:15]

        # for idx in range(0,len(procList)-1):
        #     for key in outJson[idx]["net"]:
        #         if type(outJson[idx]["net"][key][0]) == dict:
        #             immutable_dict = set([str(item) for item in outJson[idx]["net"][key]])
        #             data = [eval(i) for i in immutable_dict]
        #             outJson[idx]["net"][key] = data
        #         else:
        #             outJson[idx]["net"][key] = list(set(outJson[idx]["net"][key]))#[0:15]


        #     infoDict["Dynamic"]["Other"][key] = list(set(infoDict["Dynamic"]["Other"][key]))#[0:15]
            

        fXpcn = open(xpcn, "w")
        fXpcn.write(json.dumps(infoDict, indent=4))
        print(json.dumps(infoDict,indent=1))
        fXpcn.close()



if __name__ == "__main__":
    #classifyLogInfo(sys.argv[1])
    classifyLogInfo('/usr/local/app/HaboMalHunter/log/output.dynamic')
