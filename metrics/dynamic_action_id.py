#coding=utf-8
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
"""
Author: 
Date:	August 11, 2016
Description: Linux Malware Analysis System, Dynamic Action ID
"""
D_ID_BEGIN = 8020000
#D_ID_actionName = 802XXXX
D_ID_START_DYN = 8020001 # start the dynamic analysis, 启动动态分析
#"dynamic analysis starts"
D_ID_START_DYN_NOTE = u"start analysis time"

D_ID_STOP_DYN = 8020002 # end the dynamic analysis, 结束动态分析
#"dynamic analysis ends"
D_ID_STOP_DYN_NOTE = u"end analysis time"

D_ID_LAUNCH = 8020003 # launch the program, 启动程序
#"launch the program"
D_ID_LAUNCH_NOTE = u"start sample time"

D_ID_TERMINATE = 8020004
#"terminate the program"
D_ID_TERMINATE_NOTE = u"end sample time"


########################
# Category: Process 
# ID Range: 8020005 - 8020200
########################
D_ID_SYSCALL_CLONE = 8020005
#"clone syscall, fork or vfork"
D_ID_SYSCALL_CLONE_NOTE = u"clone"

D_ID_SYSCALL_EXECVE = 8020006
#"execve syscall, execute a file"
D_ID_SYSCALL_EXECVE_NOTE = u"load"
D_ID_PROC_EXIT = 8020007
#"process exit"
D_ID_PROC_EXIT_NOTE = u"process terminate"

# NEW ADD
D_ID_LIBC_kill = 8020008
D_ID_LIBC_kill_NOTE = u"send signal"

D_ID_LIBC_getpid = 8020009
D_ID_LIBC_getpid_NOTE = u"get self pid"

D_ID_LIBC_fork = 8020010
D_ID_LIBC_fork_NOTE = u"fork"

D_ID_LIBC_wait = 8020011
D_ID_LIBC_wait_NOTE = u"wait subprocess"

# Ver4, 30 Sept, 2016
D_ID_LIBC_system = 8020012
D_ID_LIBC_system_NOTE = u"exec_cmd"

"""
The calling process will be the only process in the new process group
and in the new session.  The new session has no controlling terminal
"""
# not be shown
D_ID_LIBC_setsid = 8020013
D_ID_LIBC_setsid_NOTE = u"setsid"

# add at 2016.10.17
D_ID_SYSCALL_ALL = 8020014
D_ID_SYSCALL_ALL_NOTE = u"syscall seq"

# add at 2016.11.07
D_ID_SYSCALL_SEQ = 8020015
D_ID_SYSCALL_SEQ_NOTE = u"syscall sequence number"
########################
# Category: File IO 
# ID Range: 8020201 - 8020400
########################

D_ID_SYSCALL_KILL = 8020200
D_ID_SYSCALL_KILL_NOTE = u"kill"

D_ID_SYSCALL_OPEN = 8020201
#"file open"
D_ID_SYSCALL_OPEN_NOTE = u"open"

D_ID_SYSCALL_READ = 8020202
#"file read"
D_ID_SYSCALL_READ_NOTE = u"read"

D_ID_SYSCALL_WRITE = 8020203
#"file write"
D_ID_SYSCALL_WRITE_NOTE = u"write"

# NEW ADD
D_ID_LIBC_remove = 8020204
D_ID_LIBC_remove_NOTE = u"delete"

D_ID_LIBC_rename = 8020205
D_ID_LIBC_rename_NOTE = u"rename"

D_ID_LIBC_readdir = 8020206
D_ID_LIBC_readdir_NOTE = u"read file"

# Ver4, 30 Sept, 2016
"""
The dup() system call creates a copy of the file descriptor oldfd,
using the lowest-numbered unused file descriptor for the new descriptor.
"""
D_ID_LIBC_dup = 8020207
D_ID_LIBC_dup_NOTE = u"dup"

D_ID_LIBC_dup2 = 8020208
D_ID_LIBC_dup2_NOTE = u"dup2"

D_ID_SYSCALL_CLOSE = 8020209
D_ID_SYSCALL_CLOSE_NOTE = u"close file"

# Ver4, 4 NOV, 2016

D_ID_SELF_DELETE = 8020210
D_ID_SELF_DELETE_NOTE = u"self del"

D_ID_SELF_MODIFIED = 8020211
D_ID_SELF_MODIFIED_NOTE = u"self modify"

D_ID_FILE_LOCK = 8020212
D_ID_FILE_LOCK_NOTE = u"self lock"

D_ID_FILE_PATH_INFO = 8020213
D_ID_FILE_PATH_INFO_NOTE = u"operation file"

########################
# Category: Network 
# ID Range: 8020401 - 8020600
########################

D_ID_NET_SOCEKT = 8020401
#"create socket"
D_ID_NET_SOCEKT_NOTE = u"socket"

D_ID_NET_CONNECT = 8020402
#connect
D_ID_NET_CONNECT_NOTE= u"connect"

D_ID_NET_DNS_QUERY = 8020403
D_ID_NET_DNS_QUERY_NOTE = u"query_dns"

D_ID_NET_DNS_RESPONSE = 8020404
D_ID_NET_DNS_RESPONSE_NOTE = u"response_dns"

D_ID_NET_HTTP_SEND = 8020405
D_ID_NET_HTTP_SEND_NOTE = u"send_http"

D_ID_NET_HTTP_RESPONSE = 8020406
D_ID_NET_HTTP_RESPONSE_NOTE = u"recv_http"

D_ID_NET_TCP = 8020407
D_ID_NET_TCP_NOTE= u"TCP_package"

D_ID_NET_HTTPS = 8020408
D_ID_NET_HTTPS_NOTE=u"HTTPS_package"

D_ID_NET_CERT = 8020409
D_ID_NET_CERT_NOTE=u"SSL Certificate"

D_ID_NET_UDP = 8020410
D_ID_NET_UDP_NOTE = u"UDP transfer"

D_ID_NET_SENDTO = 8020411
D_ID_NET_SENDTO_NOTE = u"sendto"

D_ID_LIBC_gethostbyname = 8020414
D_ID_LIBC_gethostbyname_NOTE = u"gethostbyname"

D_ID_LIBC_bind = 8020415
D_ID_LIBC_bind_NOTE = u"ip bind"

# not be shown
D_ID_LIBC_send = 8020416
D_ID_LIBC_send_NOTE = u"send"

# not be shown
D_ID_LIBC_recv = 8020417
D_ID_LIBC_recv_NOTE = u"recv"

# not be shown
D_ID_LIBC_listen = 8020418
D_ID_LIBC_listen_NOTE = u"listen"

# not be shown
D_ID_LIBC_accept = 8020419
D_ID_LIBC_accept_NOTE = u"accept"

# add Nov 15, not be shown
D_ID_NET_IP_INFO = 8020420
D_ID_NET_IP_INFO_NOTE = u"ip port"

# add Nov 23, not be shown
D_ID_NET_DNS_INFO = 8020421
D_ID_NET_DNS_INFO_NOTE = u"dns host"

D_ID_NET_URL_INFO = 8020422
D_ID_NET_URL_INFO_NOTE = u"url"
########################
# Category: Others 
# ID Range: 8020601 - 8020800
########################
# not be shown
D_ID_LIBC_dlopen = 8020601
D_ID_LIBC_dlopen_NOTE = u"load dynamic libray"
# not be shown
D_ID_LIBC_dlsym = 8020602
D_ID_LIBC_dlsym_NOTE = u"import static libray"

D_ID_LIBC_printf = 8020603
D_ID_LIBC_printf_NOTE = u"format output"

D_ID_LIBC_puts = 8020604
D_ID_LIBC_puts_NOTE = u"string output"

D_ID_LIBC_sprintf = 8020605
D_ID_LIBC_sprintf_NOTE = u"operation string"

########################
# Category: Error
# ID Range: 8020801 - 8020900
########################

D_ID_ERROR_NOEXE = 8020801
D_ID_ERROR_NOEXE_NOTE = u"cannot execute"

D_ID_END = 8029999