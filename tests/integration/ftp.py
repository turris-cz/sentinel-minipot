#!/usr/bin/env python3
from utils import *
import proxy
import time

FTP_200_RESP = b"200 COMMAND OK\r\n"
FTP_211_FEAT_RESP = b"211 FEATURES\r\n EPRT\r\n EPSV\r\n SIZE\r\n OPTS\r\n MLST\r\n MLSD\r\n MDTM\r\n LPRT\r\n LPSV\r\n211 END\r\n"
FTP_220_WELCOME_RESP = b"220 SERVICE READY\r\n"
FTP_220_REIN_RESP = b"220 READY FOR A NEW USER\r\n"
FTP_221_RESP = b"221 CLOSING CONTROL CONNECTION\r\n"
FTP_331_RESP = b"331 NEED PASSWORD FOR LOGIN\r\n"
FTP_421_RESP = b"421 CLOSING CONTROL CONNECTION\r\n"
FTP_500_RESP = b"500 SYNTAX ERROR, UNRECOGNIZED COMMAND\r\n"
FTP_501_RESP = b"501 SYNTAX ERROR, NO ARGUMENT ALLOWED\r\n"
FTP_503_RESP = b"503 BAD SEQUENCE OF COMMANDS\r\n"
FTP_530_RESP = b"530 NOT LOGGED IN\r\n"



def gen_cmd(cmd, param=""):
    """ Generates byte string from given comand and parameters 
        cmd - string 
        param -  string 
        return bytes """
    if not cmd or not cmd.strip():
        raise Exception("gen_cmd - cmd must NOT be empty")
    if param:
        return cmd.encode() + b" " + param.encode() + b"\r\n"
    else:
        return cmd.encode() + b"\r\n"


def gen_user_cmd(user=""):
    """ 
    specifies user for login
    user - string """
    return gen_cmd("user", user)


def gen_pass_cmd(passv=""):
    """ 
    must immediatley follow user cmd
    completes user's identification
    passv - string """
    return gen_cmd("pass", passv)


def gen_acct_cmd(acc_info=""):
    """ specifies account e.g for various acces levels
    not neccesarily related to user
    acc_info - account identification - string """
    return gen_cmd("acct", acc_info)


def gen_cwd_cmd(path=""):
    """ change working directory 
    path - path to change - string"""
    return gen_cmd("cwd", path)


def gen_cdup_cmd(param=""):
    """ change to parent directory """
    return gen_cmd("cdup", param)


def gen_smnt_cmd(path=""):
    """ structure mount
    for mounting different file system without altering login 
    path - path for mounting - string"""
    return gen_cmd("smnt", path)


def gen_quit_cmd(param=""):
    """ terminates user session
        and if no data transfer is in progress closes control connection"""
    return gen_cmd("quit", param)


def gen_rein_cmd(param=""):
    """ terminates user session
        flushes all account info
        control connection is left open
        same state as freshly opened control connection """
    return gen_cmd("rein", param)


def gen_port_cmd(host_port=""):
    """ spedifies data port for data connection """
    return gen_cmd("port", host_port)


def gen_pasv_cmd(param=""):
    """ request to server to listen on data port and wait for connection
    passive mode """
    return gen_cmd("pasv", param)


def gen_type_cmd(type_code=""):
    """  specifies representation type 
    type_code  - code of representation - string"""
    return gen_cmd("type", type_code)


def gen_stru_cmd(struct_code=""):
    """ specifies file structure 
    struct_code - string"""
    return gen_cmd("stru", struct_code)


def gen_mode_cmd(mode=""):
    """ specifies data transfer mode 
        mode - string """
    return gen_cmd("mode", mode)


def gen_retr_cmd(path=""):
    """ request to server to transfer a copy of a file
    path - string """
    return gen_cmd("retr", path)


def gen_stor_cmd(path=""):
    """ requests server to accpet data transfered over data connection and store it at defined path
    path - string """
    return gen_cmd("stor", path)


def gen_stou_cmd(param=""):
    """ requests server to accept data from data connection and store it in current directory under a unique name in that dir """
    return gen_cmd("stou", param)


def gen_appe_cmd(path=""):
    """  requests server to accept data from a data connection and store it at server
        if the specified file exists - data is appended to the file
        if file doesn't exist - the file is created
        path - string """
    return gen_cmd("appe", path)


def gen_allo_cmd(param=""):
    """ requests server to reserve sufficient  storage to accomodate the new file to be transfered
        param - string """
    return gen_cmd("allo", param)
    


def gen_rest_cmd(marker=""):
    """ requests server to restart file transfer at given marker
        marker - string """
    return gen_cmd("rest", marker)


def gen_rnfr_cmd(path=""):
    """ specifies old name of the file to be renamed
        path - string """
    return gen_cmd("rnfr", path)


def gen_rnto_cmd(path=""):
    """ specifies new name of the file to be renamed
    rnfr cmd must be immediately preceds 
    path - string """
    return gen_cmd("rnto", path)


def gen_abor_cmd(param=""):
    """ tells a server to abort the previous service cmd and any associated data transfer """
    return gen_cmd("abor", param)


def gen_dele_cmd(path=""):
    """ delete specified file at a server 
        path - string """
    return gen_cmd("dele", path)


def gen_rmd_cmd(path=""):
    """ removes specified directiory
        path - string """
    return gen_cmd("rmd", path)


def gen_mkd_cmd(path=""):
    """ creates a directory
        path - string """
    return gen_cmd("mkd", path)


def gen_pwd_cmd(param=""):
    """ print working directory """
    return gen_cmd("pwd", param)


def gen_list_cmd(path=""):
    """ requst to transfer list of files in specified path  to passive
        path - string """
    return gen_cmd("list", path)


def gen_nlst_cmd(path=""):
    """ sends directory listing from server to client
        output is in machine readable format
        path - string """
    return gen_cmd("nlst", path)


def gen_site_cmd(param=""):
    """  server specific srvices not included in standard commands
        param - string """
    return gen_cmd("site", param)


def gen_syst_cmd(param=""):
    """ info about OS at the server machine """
    return gen_cmd("syst", param)


def gen_stat_cmd(path=""):
    """ - requests status of progress of data transfer over data connection
        - if path is defined - as list cmd
        - general status information  """
    return gen_cmd("stat", path)


def gen_help_cmd(param=""):
    """ requests server for helpful information about its implementation status over control connection """
    return gen_cmd("help", param)


def gen_noop_cmd(param=""):
    """ no action - server should reply OK """
    return gen_cmd("noop", param)


def gen_adat_cmd(base64data=""):
    """ authentication/security data 
        base64data - string """
    return gen_cmd("adat", base64data)


def gen_auth_cmd(param=""):
    """ specifies authorization mechanism
        param - string """
    return gen_cmd("auth", param)


def gen_ccc_cmd(param=""):
    """ clear command channel - cancels commands protection """
    return gen_cmd("ccc", param)


def gen_conf_cmd(base64data=""):
    """ confidentiality protected command
        base64data - string """
    return gen_cmd("conf", base64data)


def gen_enc_cmd(base64data=""):
    """ privacy protected command
        base64data -  string """
    return gen_cmd("enc", base64data)


def gen_eprt_cmd(param=""):
    """ specifies extend address for a data connection - IPv6, NAT
        param - string """
    return gen_cmd("eprt", param)


def gen_epsv_cmd(param=""):
    """ pasive mode - see pasv cmd - extended data port format - IPv6, NAT
        param - string """
    return gen_cmd("epsv", param)


def gen_feat_cmd(param=""):
    """ requests a server to list all extension commands """
    return gen_cmd("feat",param)


def gen_host_cmd(virt_host=""):
    """ to determine to which virtual host a client wishes to connect
        virt_host - string """
    return gen_cmd("host", virt_host)


def gen_lang_cmd(lang=""):
    """ to set in which languge to to present server textual parts of command responses
        lang - code of a language - string """
    return gen_cmd("lang", lang)


def gen_lprt_cmd(long_host_port=""):
    """ see port cmd - long address for port - support for additional address families, variable length address etc.
        long_host_port - string """
    return gen_cmd("lprt", long_host_port)


def gen_lpsv_cmd(param=""):
    """ see pasv cmd - long address for non default port for waiting - support for additional address families etc.  """
    return gen_cmd("lpsv", param)


def gen_mdtm_cmd(path=""):
    """ modification time - to determine  when a file in a server was last modified
        path - defines a file - string """
    return gen_cmd("mdtm", path)


def gen_mic_cmd(base64data=""):
    """ integrity protected command
        base64data - string """
    return gen_cmd("mic", base64data)


def gen_mlsd_cmd(path=""):
    """ provides machine readable exactly defined listing of a given directory on a server
        path - defines the directory - string """
    return gen_cmd("mlsd", path)


def gen_mlst_cmd(path=""):
    """ provides data in exactly defined machine readlable format about an object on a server
        path - defines the object - string """
    return gen_cmd("mlst", path)


def gen_opts_cmd(param=""):
    """ allows a client to specify of desired behaviour of server for next command
        param - string """
    return gen_cmd("opts", param)


def gen_pbsz_cmd(size=""):
    """ defines protection buffer size - maximum encoded data block to be sent or received during file transfer
        size  - string """
    return gen_cmd("pbsz", size)


def gen_prot_cmd(prot_code=""):
    """ specifies data channel protection level
        prot_code - string """
    return gen_cmd("prot", prot_code)


def gen_size_cmd(path=""):
    """ to obtain the transfer size of a file form a server
        path - defines a file - string """
    return gen_cmd("size", path)


# proxy reports

def gen_synt_err_report(ip):
    """ Generates proxy report syntax message.
        ip - string
        returns dictionary"""
    return proxy.gen_syntax_error_report(ip, "ftp")


def gen_connect_report(ip):
    """ Generates proxy report connect message.
        ip - string 
        returns dictionary """
    return proxy.gen_connect_report(ip, "ftp")


def gen_disconnect_report(ip):
    """ Generates proxy report disconnect message. 
        ip - string
        returns dictionary"""
    return proxy.gen_disconnect_report(ip, "ftp")


def gen_login_report(ip, user="", password=""):
    """ Generates proxy report login message.
        user -  string
        password - string
        returns dictionary"""
    data = {}
    if user:
        data["user"] = user
    if password:
        data["password"] = password
    return proxy.gen_proxy_report("ftp", "login", ip, data)

def abor_cmd_handler(server_sock):
    """ Sends abor command.
        returns list of proxy reports - list of dictionaries """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_220_WELCOME_RESP)
    cmd = gen_abor_cmd()
    send_to_sock(server_sock, cmd)
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_530_RESP)
    return reports


def acct_cmd_handler(server_sock):
    """ Sends acct command.
        returns list of proxy reports - list of dictionaries """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_220_WELCOME_RESP)
    acc_info = gen_rand_printable_str(50)
    cmd = gen_acct_cmd(acc_info)
    send_to_sock(server_sock, cmd)
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_530_RESP)
    return reports


def adat_cmd_handler(server_sock):
    """ Sends adat command.
        returns list of proxy reports - list of dictionaries """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_220_WELCOME_RESP)
    cmd = gen_adat_cmd(gen_rand_printable_str(50))
    send_to_sock(server_sock, cmd)
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_500_RESP)
    return reports


def allo_cmd_handler(server_sock):
    """ Sends ALLO command.
        returns list of proxy reports - list of dictionaries """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_220_WELCOME_RESP)
    cmd = gen_abor_cmd()
    send_to_sock(server_sock, cmd)
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_530_RESP)
    return reports


def appe_cmd_handler(server_sock):
    """ Sends APPE command.
        returns list of proxy reports - list of dictionaries """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_220_WELCOME_RESP)
    cmd = gen_appe_cmd(gen_rand_printable_str(50))
    send_to_sock(server_sock, cmd)
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_530_RESP)
    return reports


def auth_cmd_handler(server_sock):
    """ Sends AUTH command.
        returns list of proxy reports - list of dictionaries """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_220_WELCOME_RESP)
    cmd = gen_auth_cmd(gen_rand_printable_str(50))
    send_to_sock(server_sock, cmd)
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_500_RESP)
    return reports


def ccc_cmd_handler(server_sock):
    """ Sends CCC command.
        returns list of proxy reports - list of dictionaries """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_220_WELCOME_RESP)
    cmd = gen_ccc_cmd()
    send_to_sock(server_sock, cmd)
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_500_RESP)
    return reports


def cdup_cmd_handler(server_sock):
    """ Sends CDUP command.
        returns list of proxy reports - list of dictionaries """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_220_WELCOME_RESP)
    cmd = gen_cdup_cmd()
    send_to_sock(server_sock, cmd)
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_530_RESP)
    return reports


def conf_cmd_handler(server_sock):
    """ Sends CONF command.
        returns list of proxy reports - list of dictionaries """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_220_WELCOME_RESP)
    cmd = gen_conf_cmd(gen_rand_printable_str(50))
    send_to_sock(server_sock, cmd)
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_500_RESP)
    return reports


def cwd_cmd_handler(server_sock):
    """ Sends CWD command.
        returns list of proxy reports - list of dictionaries """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_220_WELCOME_RESP)
    cmd = gen_cwd_cmd(gen_rand_printable_str(50))
    send_to_sock(server_sock, cmd)
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_530_RESP)
    return reports


def dele_cmd_handler(server_sock):
    """ Sends DELE command.
        returns list of proxy reports - list of dictionaries """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_220_WELCOME_RESP)
    cmd = gen_dele_cmd(gen_rand_printable_str(50))
    send_to_sock(server_sock, cmd)
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_530_RESP)
    return reports


def enc_cmd_handler(server_sock):
    """ Sends ENC command.
        returns list of proxy reports - list of dictionaries """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_220_WELCOME_RESP)
    cmd = gen_enc_cmd(gen_rand_printable_str(50))
    send_to_sock(server_sock, cmd)
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_500_RESP)
    return reports


def eprt_cmd_handler(server_sock):
    """ Sends EPRT command.
        returns list of proxy reports - list of dictionaries """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_220_WELCOME_RESP)
    cmd = gen_eprt_cmd(gen_rand_printable_str(50))
    send_to_sock(server_sock, cmd)
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_530_RESP)
    return reports


def epsv_cmd_handler(server_sock):
    """ Sends EPSV command.
        returns list of proxy reports - list of dictionaries """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_220_WELCOME_RESP)
    cmd = gen_epsv_cmd(gen_rand_printable_str(50))
    send_to_sock(server_sock, cmd)
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_530_RESP)
    return reports


def feat_cmd_handler(server_sock):
    """ Sends FEAT command.
        returns list of proxy reports - list of dictionaries """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_220_WELCOME_RESP)
    cmd = gen_feat_cmd()
    send_to_sock(server_sock, cmd)
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_211_FEAT_RESP)
    return reports


def feat_with_param_cmd_handler(server_sock):
    """ Sends FEAT command with param - syntax error.
        returns list of proxy reports - list of dictionaries """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_220_WELCOME_RESP)
    cmd = gen_feat_cmd(gen_rand_printable_str(50))
    send_to_sock(server_sock, cmd)
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_501_RESP)
    return reports


def help_cmd_handler(server_sock):
    """ Sends HELP command.
        returns list of proxy reports - list of dictionaries """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_220_WELCOME_RESP)
    cmd = gen_help_cmd(gen_rand_printable_str(50))
    send_to_sock(server_sock, cmd)
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_530_RESP)
    return reports


def host_cmd_handler(server_sock):
    """ Sends HOST command.
        returns list of proxy reports - list of dictionaries """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_220_WELCOME_RESP)
    cmd = gen_host_cmd(gen_rand_printable_str(50))
    send_to_sock(server_sock, cmd)
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_500_RESP)
    return reports


def lang_cmd_handler(server_sock):
    """ Sends LANG command.
        returns list of proxy reports - list of dictionaries """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_220_WELCOME_RESP)
    cmd = gen_lang_cmd(gen_rand_printable_str(50))
    send_to_sock(server_sock, cmd)
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_500_RESP)
    return reports


def list_cmd_handler(server_sock):
    """ Sends LIST command.
        returns list of proxy reports - list of dictionaries """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_220_WELCOME_RESP)
    cmd = gen_list_cmd(gen_rand_printable_str(50))
    send_to_sock(server_sock, cmd)
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_530_RESP)
    return reports


def lprt_cmd_handler(server_sock):
    """ Sends LPRT command.
        returns list of proxy reports - list of dictionaries """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_220_WELCOME_RESP)
    cmd = gen_lprt_cmd(gen_rand_printable_str(50))
    send_to_sock(server_sock, cmd)
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_530_RESP)
    return reports



def lpsv_cmd_handler(server_sock):
    """ Sends LPSV command.
        returns list of proxy reports - list of dictionaries """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_220_WELCOME_RESP)
    cmd = gen_lpsv_cmd()
    send_to_sock(server_sock, cmd)
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_530_RESP)
    return reports



def mdtm_cmd_handler(server_sock):
    """ Sends MDTM command.
        returns list of proxy reports - list of dictionaries """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_220_WELCOME_RESP)
    cmd = gen_mdtm_cmd(gen_rand_printable_str(50))
    send_to_sock(server_sock, cmd)
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_530_RESP)
    return reports



def mic_cmd_handler(server_sock):
    """ Sends MIC command.
        returns list of proxy reports - list of dictionaries """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_220_WELCOME_RESP)
    cmd = gen_mic_cmd(gen_rand_printable_str(50))
    send_to_sock(server_sock, cmd)
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_500_RESP)
    return reports



def mkd_cmd_handler(server_sock):
    """ Sends MKD command.
        returns list of proxy reports - list of dictionaries """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_220_WELCOME_RESP)
    cmd = gen_mkd_cmd(gen_rand_printable_str(50))
    send_to_sock(server_sock, cmd)
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_530_RESP)
    return reports



def mlsd_cmd_handler(server_sock):
    """ Sends MLSD command.
        returns list of proxy reports - list of dictionaries """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_220_WELCOME_RESP)
    cmd = gen_mlsd_cmd(gen_rand_printable_str(50))
    send_to_sock(server_sock, cmd)
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_530_RESP)
    return reports



def mlst_cmd_handler(server_sock):
    """ Sends MLST command.
        returns list of proxy reports - list of dictionaries """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_220_WELCOME_RESP)
    cmd = gen_mlst_cmd(gen_rand_printable_str(50))
    send_to_sock(server_sock, cmd)
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_530_RESP)
    return reports



def mode_cmd_handler(server_sock):
    """ Sends MODE command.
        returns list of proxy reports - list of dictionaries """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_220_WELCOME_RESP)
    cmd = gen_mode_cmd(gen_rand_printable_str(50))
    send_to_sock(server_sock, cmd)
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_530_RESP)
    return reports



def nlst_cmd_handler(server_sock):
    """ Sends NLST command.
        returns list of proxy reports - list of dictionaries """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_220_WELCOME_RESP)
    cmd = gen_nlst_cmd(gen_rand_printable_str(50))
    send_to_sock(server_sock, cmd)
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_530_RESP)
    return reports



def noop_cmd_handler1(server_sock):
    """ Sends NOOP command with no parameters.
        returns list of proxy reports - list of dictionaries """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_220_WELCOME_RESP)
    cmd = gen_noop_cmd()
    send_to_sock(server_sock, cmd)
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_200_RESP)
    return reports


def noop_cmd_handler2(server_sock):
    """ Sends NOOP command with random parameter. It should cause syntax error.
        returns list of proxy reports - list of dictionaries """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_220_WELCOME_RESP)
    cmd = gen_noop_cmd(gen_rand_printable_str(40))
    send_to_sock(server_sock, cmd)
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_501_RESP)
    return reports


def opts_cmd_handler(server_sock):
    """ Sends OPTS command.
        returns list of proxy reports - list of dictionaries """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_220_WELCOME_RESP)
    cmd = gen_opts_cmd(gen_rand_printable_str(50))
    send_to_sock(server_sock, cmd)
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_530_RESP)
    return reports



def pass_cmd_handler1(server_sock):
    """ Sends PASS command with random password as a parameter.
        returns list of proxy reports - list of dictionaries """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_220_WELCOME_RESP)
    cmd = gen_pass_cmd(gen_rand_printable_str(50))
    send_to_sock(server_sock, cmd)
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_503_RESP)
    return reports


def pass_cmd_handler2(server_sock):
    """ Sends PASS command without password as param. It causes syntax error.
        returns list of proxy reports - list of dictionaries """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_220_WELCOME_RESP)
    cmd = gen_pass_cmd()
    send_to_sock(server_sock, cmd)
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_501_RESP)
    return reports


def pasv_cmd_handler(server_sock):
    """ Sends PASV command.
        returns list of proxy reports - list of dictionaries """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_220_WELCOME_RESP)
    cmd = gen_pasv_cmd()
    send_to_sock(server_sock, cmd)
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_530_RESP)
    return reports



def pbsz_cmd_handler(server_sock):
    """ Sends PBSZ command.
        returns list of proxy reports - list of dictionaries """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_220_WELCOME_RESP)
    cmd = gen_pbsz_cmd(gen_rand_printable_str(50))
    send_to_sock(server_sock, cmd)
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_500_RESP)
    return reports



def port_cmd_handler(server_sock):
    """ Sends PORT command.
        returns list of proxy reports - list of dictionaries """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_220_WELCOME_RESP)
    cmd = gen_port_cmd(gen_rand_printable_str(50))
    send_to_sock(server_sock, cmd)
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_530_RESP)
    return reports



def prot_cmd_handler(server_sock):
    """ Sends HOST command.
        returns list of proxy reports - list of dictionaries """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_220_WELCOME_RESP)
    cmd = gen_prot_cmd(gen_rand_printable_str(50))
    send_to_sock(server_sock, cmd)
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_500_RESP)
    return reports



def pwd_cmd_handler(server_sock):
    """ Sends PWD command.
        returns list of proxy reports - list of dictionaries """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_220_WELCOME_RESP)
    cmd = gen_pwd_cmd()
    send_to_sock(server_sock, cmd)
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_530_RESP)
    return reports



def quit_cmd_handler1(server_sock):
    """ Sends QUIT command with no parameter.
        returns list of proxy reports - list of dictionaries """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_220_WELCOME_RESP)
    cmd = gen_quit_cmd()
    send_to_sock(server_sock, cmd)
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_221_RESP)
    return reports


def quit_cmd_handler2(server_sock):
    """ Sends QUIT command with random parameter. It should cause syntax error.
        returns list of proxy reports - list of dictionaries """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_220_WELCOME_RESP)
    cmd = gen_quit_cmd(gen_rand_printable_str(50))
    send_to_sock(server_sock, cmd)
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_501_RESP)
    return reports


def rein_cmd_handler1(server_sock):
    """ Sends REIN command with no paramter.
        returns list of proxy reports - list of dictionaries """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_220_WELCOME_RESP)
    cmd = gen_rein_cmd()
    send_to_sock(server_sock, cmd)
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_220_REIN_RESP)
    return reports


def rein_cmd_handler2(server_sock):
    """ Sends REIN command with random parameter. It should cause syntax error. 
        returns list of proxy reports - list of dictionaries """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_220_WELCOME_RESP)
    cmd = gen_rein_cmd(gen_rand_printable_str(50))
    send_to_sock(server_sock, cmd)
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_501_RESP)
    return reports


def rest_cmd_handler(server_sock):
    """ Sends REST command.
        returns list of proxy reports - list of dictionaries """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_220_WELCOME_RESP)
    cmd = gen_rest_cmd(gen_rand_printable_str(50))
    send_to_sock(server_sock, cmd)
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_530_RESP)
    return reports



def retr_cmd_handler(server_sock):
    """ Sends RETR command.
        returns list of proxy reports - list of dictionaries """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_220_WELCOME_RESP)
    cmd = gen_retr_cmd(gen_rand_printable_str(50))
    send_to_sock(server_sock, cmd)
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_530_RESP)
    return reports


def rmd_cmd_handler(server_sock):
    """ Sends RMD command.
        returns list of proxy reports - list of dictionaries """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_220_WELCOME_RESP)
    cmd = gen_rmd_cmd(gen_rand_printable_str(50))
    send_to_sock(server_sock, cmd)
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_530_RESP)
    return reports



def rnfr_cmd_handler(server_sock):
    """ Sends RNFR command.
        returns list of proxy reports - list of dictionaries """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_220_WELCOME_RESP)
    cmd = gen_rnfr_cmd(gen_rand_printable_str(50))
    send_to_sock(server_sock, cmd)
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_530_RESP)
    return reports



def rnto_cmd_handler(server_sock):
    """ Sends RNTO command.
        returns list of proxy reports - list of dictionaries """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_220_WELCOME_RESP)
    cmd = gen_rnto_cmd(gen_rand_printable_str(50))
    send_to_sock(server_sock, cmd)
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_530_RESP)
    return reports


def site_cmd_handler(server_sock):
    """ Sends SITE command.
        returns list of proxy reports - list of dictionaries """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_220_WELCOME_RESP)
    cmd = gen_site_cmd(gen_rand_printable_str(50))
    send_to_sock(server_sock, cmd)
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_530_RESP)
    return reports


def size_cmd_handler(server_sock):
    """ Sends SIZE command.
        returns list of proxy reports - list of dictionaries """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_220_WELCOME_RESP)
    cmd = gen_size_cmd(gen_rand_printable_str(50))
    send_to_sock(server_sock, cmd)
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_530_RESP)
    return reports


def smnt_cmd_handler(server_sock):
    """ Sends SMNT command.
        returns list of proxy reports - list of dictionaries """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_220_WELCOME_RESP)
    cmd = gen_rnfr_cmd(gen_rand_printable_str(50))
    send_to_sock(server_sock, cmd)
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_530_RESP)
    return reports


def stat_cmd_handler(server_sock):
    """ Sends STAT command.
        returns list of proxy reports - list of dictionaries """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_220_WELCOME_RESP)
    cmd = gen_stat_cmd(gen_rand_printable_str(50))
    send_to_sock(server_sock, cmd)
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_530_RESP)
    return reports


def stor_cmd_handler(server_sock):
    """ Sends STOR command.
        returns list of proxy reports - list of dictionaries """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_220_WELCOME_RESP)
    cmd = gen_stor_cmd(gen_rand_printable_str(50))
    send_to_sock(server_sock, cmd)
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_530_RESP)
    return reports


def stou_cmd_handler(server_sock):
    """ Sends STOU command.
        returns list of proxy reports - list of dictionaries """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_220_WELCOME_RESP)
    cmd = gen_stou_cmd()
    send_to_sock(server_sock, cmd)
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_530_RESP)
    return reports


def stru_cmd_handler(server_sock):
    """ Sends STRU command.
        returns list of proxy reports - list of dictionaries """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_220_WELCOME_RESP)
    cmd = gen_stru_cmd(gen_rand_printable_str(50))
    send_to_sock(server_sock, cmd)
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_530_RESP)
    return reports


def syst_cmd_handler(server_sock):
    """ Sends SYST command.
        returns list of proxy reports - list of dictionaries """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_220_WELCOME_RESP)
    cmd = gen_syst_cmd()
    send_to_sock(server_sock, cmd)
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_530_RESP)
    return reports


def type_cmd_handler(server_sock):
    """ Sends TYPE command.
        returns list of proxy reports - list of dictionaries """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_220_WELCOME_RESP)
    cmd = gen_type_cmd(gen_rand_printable_str(50))
    send_to_sock(server_sock, cmd)
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_530_RESP)
    return reports


def user_cmd_handler1(server_sock):
    """ Sends user command with random username as param.
        returns list of proxy reports - list of dictionaries """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_220_WELCOME_RESP)
    user = gen_rand_printable_str(15)
    cmd = gen_user_cmd(user)
    send_to_sock(server_sock, cmd)
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_331_RESP)
    return reports


def user_cmd_handler2(server_sock):
    """ Sends user command without no username as parameter. Syntax error is 
        returns list of proxy reports - list of dictionaries """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_220_WELCOME_RESP)
    cmd = gen_user_cmd("")
    send_to_sock(server_sock, cmd)
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_501_RESP)
    return reports


# scenarios

def brute_force_handler(server_sock):
    """ Performs brute force attack.
        return list of proxy reports - list of dictionaries  """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_220_WELCOME_RESP)
    while True:
        # username = gen_rand_printable_str(random.randrange(10, 3000))
        username = gen_rand_printable_str(random.randrange(10, 200))
        # username = "aaaaaa"
        cmd = gen_user_cmd(username)
        send_to_sock(server_sock, cmd)

        response = recv_from_sock(server_sock)
        # print(response)
        str_cmp(response, FTP_331_RESP)


        # password = gen_rand_printable_str(random.randrange(15, 3000))
        password = gen_rand_printable_str(random.randrange(15, 200))
        # password = "bbbbbb"
        cmd = gen_pass_cmd(password)
        send_to_sock(server_sock, cmd)

        reports.append(gen_login_report(ip_addr, username, password))

        response = recv_from_sock(server_sock)

        if response == FTP_530_RESP:
            continue
        if response == FTP_421_RESP:
            if not recv_from_sock(server_sock):
                # connection closed by server
                break
        raise Exception("ftp - bruteforce handler - wrong flow")

    # reports.append(gen_disconnect_report(ip_addr))

    return reports


def brute_force_interleaved_handler(server_sock):
    """ Performs brute force attack. Interleave user and pass cmd sequnce with some others commands. 
        return list of proxy reports - list of dictionaries  """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_220_WELCOME_RESP)
    while True:
        # user
        username = gen_rand_printable_str(random.randrange(10, 200))
        cmd = gen_user_cmd(username)
        send_to_sock(server_sock, cmd)
        response = recv_from_sock(server_sock)
        # print(response)
        str_cmp(response, FTP_331_RESP)
        # password
        password = gen_rand_printable_str(random.randrange(15, 200))
        cmd = gen_pass_cmd(password)
        send_to_sock(server_sock, cmd)
        reports.append(gen_login_report(ip_addr, username, password))
        response = recv_from_sock(server_sock)
        # print(response)
        if response == FTP_421_RESP:
            if not recv_from_sock(server_sock):
                # connection closed by server
                break
        str_cmp(response, FTP_530_RESP)
        # other
        cmds = [gen_acct_cmd(gen_rand_printable_str(40)),
                gen_eprt_cmd(gen_rand_printable_str(50)),
                gen_mkd_cmd(gen_rand_printable_str(40)),
                gen_pasv_cmd(),
                gen_rnfr_cmd(gen_rand_printable_str(60)),
                gen_stor_cmd(gen_rand_printable_str(45)),]
        cmd = random.choice(cmds)
        # print(cmd)
        send_to_sock(server_sock, cmd)
        response = recv_from_sock(server_sock)
        # reply for all above cmds is the same
        # print(response)
        str_cmp(response, FTP_530_RESP)
    # reports.append(gen_disconnect_report(ip_addr))
    return reports


def more_user_cmd_handler(server_sock):
    """ send more users comands and then password. It should report the username from the last user cmd.
        return list of proxy reports - list of dictionaries"""
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_220_WELCOME_RESP)
    # 1. user
    username1 = gen_rand_printable_str(random.randrange(10, 200))
    cmd = gen_user_cmd(username1)
    send_to_sock(server_sock, cmd)
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_331_RESP)
    # 2. user
    username2 = gen_rand_printable_str(random.randrange(10, 200))
    cmd = gen_user_cmd(username2)
    send_to_sock(server_sock, cmd)
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_331_RESP)
    # 3.user
    username3 = gen_rand_printable_str(random.randrange(10, 200))
    cmd = gen_user_cmd(username3)
    send_to_sock(server_sock, cmd)
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_331_RESP)
    # password
    password = gen_rand_printable_str(random.randrange(15, 200))
    cmd = gen_pass_cmd(password)
    send_to_sock(server_sock, cmd)
    reports.append(gen_login_report(ip_addr, username3, password))
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_530_RESP)
    # reports.append(gen_disconnect_report(ip_addr))
    return reports

# buffers' limits

def max_cmd_length_handler1(server_sock):
    """ send maximum allowed message size. It just time outs.
        Return list of proxy reports - list of dictionaries.  """
    ip_addr = get_ip_addr(server_sock)
    reports = [gen_connect_report(ip_addr)]
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_220_WELCOME_RESP)
    cmd = gen_rand_ascii_print_byte_str(4095)
    send_to_sock(server_sock, cmd)
    response = recv_from_sock(server_sock)
    if response:
        raise Exception("wrong flow")
    return reports


# def max_cmd_length_handler2(server_sock):
#     """ send more than maximum allowed message size. Conncetion is closed immediately.
#         return list of proxy reports - list of dictionaries  """
#     ip_addr = get_ip_addr(server_sock)
#     reports = [gen_connect_report(ip_addr)]
#     cmd = gen_rand_ascii_print_byte_str(4096)
#     send_to_sock(server_sock, cmd)
#     response = recv_from_sock(server_sock)
#     str_cmp(response, FTP_220_WELCOME_RESP)
#     response = recv_from_sock(server_sock)
#     str_cmp(response, FTP_421_RESP)
#     return reports 

# connection

# def hanging_conn_handler(server_sock):
#     """ No communication. Just hanging connection.
#         return list of proxy reports - list of dictionaries """
#     ip_addr = get_ip_addr(server_sock)
#     sent_messages = [gen_connect_report(ip_addr)]
#     response = recv_from_sock(server_sock)
#     str_cmp(response, FTP_220_WELCOME_RESP)
#     time.sleep(5)
#     response = recv_from_sock(server_sock)
#     if response:
#         raise Exception('wrong flow')
#     return sent_messages



def client_close_conn_handler(server_sock):
    """ Send one command and close connection. To check if minipot handles the situatkon properly.
        return list of proxy reports - list of dictionaries """
    ip_addr = get_ip_addr(server_sock)
    sent_messages = [gen_connect_report(ip_addr)]
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_220_WELCOME_RESP)
    cmd = gen_host_cmd(gen_rand_printable_str(50))
    send_to_sock(server_sock, cmd)
    response = recv_from_sock(server_sock)
    str_cmp(response, FTP_500_RESP)
    server_sock.close()
    return sent_messages


# syntax

# def cmd_syntax_handler1(server_sock):
#     """ Send CR but instead of LF send garbage. It is syntax error.
#         return list of proxy reports - list of dictionaries"""
#     ip_addr = get_ip_addr(server_sock)
#     sent_messages = [gen_connect_report(ip_addr)]
#     response = recv_from_sock(server_sock)
#     str_cmp(response, FTP_220_WELCOME_RESP)
#     cmd = gen_rand_ascii_print_byte_str(50) + b"\rl"
#     send_to_sock(server_sock, cmd)
#     response = recv_from_sock(server_sock)
#     str_cmp(response, FTP_421_RESP)
#     return sent_messages


# def cmd_syntax_handler2(server_sock):
#     """  """
#     ip_addr = get_ip_addr(server_sock)
#     sent_messages = [gen_connect_report(ip_addr)]
#     response = recv_from_sock(server_sock)
#     str_cmp(response, FTP_220_WELCOME_RESP)
#     cmd = gen_rand_ascii_print_byte_str(4).replace(b" ", b"") + b" " + gen_rand_byte_str(40) + b"\r\n"
#     send_to_sock(server_sock, cmd)
#     response = recv_from_sock(server_sock)
#     print(response)
#     str_cmp(response, FTP_500_RESP)
#     return sent_messages




    # sent empty command

