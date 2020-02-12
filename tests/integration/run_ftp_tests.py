#!/usr/bin/env python3

from test import Test
import ftp
import random

if __name__ == "__main__":
    # TODO change here
    random.seed(54544354343)
    proxy_sock = 'ipc:///tmp/sentinel_pull.sock'
    host = '127.0.0.1'
    port = 9000

    Test("ftp ABOR cmd test", proxy_sock, [(ftp.abor_cmd_handler, host, port )]).run()
    Test("ftp ACCT cmd test", proxy_sock, [(ftp.acct_cmd_handler, host, port )]).run()
    Test("ftp ADAT cmd test", proxy_sock, [(ftp.adat_cmd_handler, host, port )]).run()
    Test("ftp ALLO cmd test", proxy_sock, [(ftp.allo_cmd_handler, host, port )]).run()
    Test("ftp APPE cmd test", proxy_sock, [(ftp.appe_cmd_handler, host, port )]).run()
    Test("ftp AUTH cmd test", proxy_sock, [(ftp.auth_cmd_handler, host, port )]).run()
    Test("ftp CCC cmd test", proxy_sock, [(ftp.ccc_cmd_handler, host, port )]).run()
    Test("ftp CDUP cmd test", proxy_sock, [(ftp.cdup_cmd_handler, host, port )]).run()
    
    Test("ftp CONF cmd test", proxy_sock, [(ftp.conf_cmd_handler, host, port )]).run()
    Test("ftp CWD cmd test", proxy_sock, [(ftp.cwd_cmd_handler, host, port )]).run()
    Test("ftp DELE cmd test", proxy_sock, [(ftp.dele_cmd_handler, host, port )]).run()
    Test("ftp ENC cmd test", proxy_sock, [(ftp.enc_cmd_handler, host, port )]).run()
    Test("ftp EPRT cmd test", proxy_sock, [(ftp.eprt_cmd_handler, host, port )]).run()
    Test("ftp EPSV cmd test", proxy_sock, [(ftp.epsv_cmd_handler, host, port )]).run()

    Test("ftp FEAT cmd test", proxy_sock, [(ftp.feat_cmd_handler, host, port )]).run()
    Test("ftp FEAT with param cmd test", proxy_sock, [(ftp.feat_with_param_cmd_handler, host, port )]).run()
    Test("ftp HELP cmd test", proxy_sock, [(ftp.help_cmd_handler, host, port )]).run()

    Test("ftp HOST cmd test", proxy_sock, [(ftp.host_cmd_handler, host, port )]).run()
    Test("ftp LANG cmd test", proxy_sock, [(ftp.lang_cmd_handler, host, port )]).run()
    Test("ftp LIST cmd test", proxy_sock, [(ftp.list_cmd_handler, host, port )]).run()
    Test("ftp LPRT cmd test", proxy_sock, [(ftp.lprt_cmd_handler, host, port )]).run()
    Test("ftp LPSV cmd test", proxy_sock, [(ftp.lpsv_cmd_handler, host, port )]).run()
    Test("ftp MDTM cmd test", proxy_sock, [(ftp.mdtm_cmd_handler, host, port )]).run()
    Test("ftp MIC cmd test", proxy_sock, [(ftp.mic_cmd_handler, host, port )]).run()
    Test("ftp MKD cmd test", proxy_sock, [(ftp.mkd_cmd_handler, host, port )]).run()
    Test("ftp MLSD cmd test", proxy_sock, [(ftp.mlsd_cmd_handler, host, port )]).run()
    Test("ftp MLST cmd test", proxy_sock, [(ftp.mlst_cmd_handler, host, port )]).run()
    Test("ftp MODE cmd test", proxy_sock, [(ftp.mode_cmd_handler, host, port )]).run()
    Test("ftp NLST cmd test", proxy_sock, [(ftp.nlst_cmd_handler, host, port )]).run()
    Test("ftp NOOP cmd test 1", proxy_sock, [(ftp.noop_cmd_handler1, host, port )]).run()
    Test("ftp NOOP cmd test 2", proxy_sock, [(ftp.noop_cmd_handler2, host, port )]).run()
    Test("ftp OPTS cmd test", proxy_sock, [(ftp.opts_cmd_handler, host, port )]).run()
    
    Test("ftp PASS cmd test 1", proxy_sock, [(ftp.pass_cmd_handler1, host, port )]).run()
    Test("ftp PASS cmd test 2", proxy_sock, [(ftp.pass_cmd_handler2, host, port )]).run()
    Test("ftp PASV cmd test", proxy_sock, [(ftp.pasv_cmd_handler, host, port )]).run()
    Test("ftp PBSZ cmd test", proxy_sock, [(ftp.pbsz_cmd_handler, host, port )]).run()
    Test("ftp PORT cmd test", proxy_sock, [(ftp.port_cmd_handler, host, port )]).run()
    Test("ftp PROT cmd test", proxy_sock, [(ftp.prot_cmd_handler, host, port )]).run()
    Test("ftp PWD cmd test", proxy_sock, [(ftp.pwd_cmd_handler, host, port )]).run()

    Test("ftp QUIT cmd test 1", proxy_sock, [(ftp.quit_cmd_handler1, host, port )]).run()
    Test("ftp QUIT cmd test 2", proxy_sock, [(ftp.quit_cmd_handler2, host, port )]).run()
    Test("ftp REIN cmd test 1", proxy_sock, [(ftp.rein_cmd_handler1, host, port )]).run()
    Test("ftp REIN cmd test 2", proxy_sock, [(ftp.rein_cmd_handler2, host, port )]).run()
    Test("ftp REST cmd test", proxy_sock, [(ftp.rest_cmd_handler, host, port )]).run()
    Test("ftp RETR cmd test", proxy_sock, [(ftp.retr_cmd_handler, host, port )]).run()

    Test("ftp RMD cmd test", proxy_sock, [(ftp.rmd_cmd_handler, host, port )]).run()
    Test("ftp RNFR cmd test", proxy_sock, [(ftp.rnfr_cmd_handler, host, port )]).run()
    Test("ftp RNTO cmd test", proxy_sock, [(ftp.rnto_cmd_handler, host, port )]).run()
    Test("ftp SITE cmd test", proxy_sock, [(ftp.site_cmd_handler, host, port )]).run()
    Test("ftp SIZE cmd test", proxy_sock, [(ftp.size_cmd_handler, host, port )]).run()
    Test("ftp SMNT cmd test", proxy_sock, [(ftp.smnt_cmd_handler, host, port )]).run()
    Test("ftp STAT cmd test", proxy_sock, [(ftp.stat_cmd_handler, host, port )]).run()
    Test("ftp STOR cmd test", proxy_sock, [(ftp.stor_cmd_handler, host, port )]).run()
    Test("ftp STOU cmd test", proxy_sock, [(ftp.stou_cmd_handler, host, port )]).run()
    Test("ftp STRU cmd test", proxy_sock, [(ftp.stru_cmd_handler, host, port )]).run()
    Test("ftp SYST cmd test", proxy_sock, [(ftp.syst_cmd_handler, host, port )]).run()
    Test("ftp TYPE cmd test", proxy_sock, [(ftp.type_cmd_handler, host, port )]).run()
    Test("ftp USER cmd test 1", proxy_sock, [(ftp.user_cmd_handler1, host, port )]).run()
    Test("ftp USER cmd test 2", proxy_sock, [(ftp.user_cmd_handler2, host, port )]).run()

    # scenarios
    Test("ftp brute force test ", proxy_sock, [(ftp.brute_force_handler, host, port )]).run()
    Test("ftp brute force interleaved test", proxy_sock, [(ftp.brute_force_interleaved_handler, host, port )]).run()
    Test("more user cmd test", proxy_sock, [(ftp.more_user_cmd_handler, host, port )]).run()

    # buffers' limits tests
    Test("max cmd length test 1", proxy_sock, [(ftp.max_cmd_length_handler1, host, port )]).run()

    # changed behavior
    # Test("max cmd length test 2", proxy_sock, [(ftp.max_cmd_length_handler2, host, port )]).run()
    
    # Connection tests
    
    # manual testing
    # Test("hanging connection test", proxy_sock, [(ftp.hanging_conn_handler, host, port )]).run()
    
    Test("client close connection test", proxy_sock, [(ftp.client_close_conn_handler, host, port )]).run()
    handlers = [(ftp.brute_force_handler, host, port ), 
                (ftp.brute_force_handler, host, port ),
                (ftp.brute_force_handler, host, port ),
                (ftp.brute_force_handler, host, port ),
                (ftp.brute_force_handler, host, port )]
    Test("multiple connection test", proxy_sock, handlers).run()

    # syntax
    # Test("syntax test 1", proxy_sock, [(ftp.cmd_syntax_handler1, host, port )]).run()
    # Test("syntax test 2", proxy_sock, [(ftp.cmd_syntax_handler2, host, port )]).run()
