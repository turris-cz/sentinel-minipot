#!/bin/bash

test_type="$1"
minipot_type="$2"

case "$test_type" in
	"m"|"manual")
		test_mesg="manual"
		case "$minipot_type" in
			"f"|"ftp")
				minipot_mesg="ftp"
				socket_arg="ipc:///tmp/sentinel_pull1.sock"
				minipot_arg="-F 9001"
				;;
			"h"|"http")
				minipot_mesg="http"
				socket_arg="ipc:///tmp/sentinel_pull2.sock"
				minipot_arg="-H 9002"
				;;
			"s"|"smtp")
				minipot_mesg="smtp"
				socket_arg="ipc:///tmp/sentinel_pull3.sock"
				minipot_arg="-S 9003"
				;;
			"t"|"telnet")
				minipot_mesg="telnet"
				socket_arg="ipc:///tmp/sentinel_pull4.sock"
				minipot_arg="-T 9004"
				;;
			*)
				echo "Minipot type $minipot_type is invlaid."
				exit 1
				;;
		esac
		;;
	"i"|"integration")
		test_mesg="integration"
		case "$minipot_type" in
			"f"|"ftp")
				minipot_mesg="ftp"
				socket_arg="ipc:///tmp/sentinel_pull5.sock"
				minipot_arg="-F 9005"
				;;
			"h"|"http")
				minipot_mesg="http"
				socket_arg="ipc:///tmp/sentinel_pull6.sock"
				minipot_arg="-H 9006"
				;;
			"s"|"smtp")
				minipot_mesg="smtp"
				socket_arg="ipc:///tmp/sentinel_pull7.sock"
				minipot_arg="-S 9007"
				;;
			"t"|"telnet")
				minipot_mesg="telnet"
				socket_arg="ipc:///tmp/sentinel_pull8.sock"
				minipot_arg="-T 9008"
				;;
			*)
				echo "Minipot type $minipot_type is invlaid."
				exit 1
				;;
		esac
		;;
	"p"|"pipeline")
		test_mesg="pipeline"
		minipot_mesg="ftp http smtp telnet"
		socket_arg="ipc:///tmp/sentinel_pull.sock"
		minipot_arg="-F 9015 -H 9016 -S 9017 -T 9018"
		;;
	"t"|"throughput")
		test_mesg="throughput"
		minipot_mesg="ftp http smtp telnet"
		socket_arg="ipc:///tmp/sentinel_pull10.sock"
		minipot_arg="-F 9020 -H 9021 -S 9022 -T 9023"
		;;
	*)
		echo "Test type $test_type is not valid."
		exit 1
		;;
esac

echo "$minipot_mesg minipot for $test_mesg tests running"
echo "--------------------------------------------------------------"

valgrind \
--leak-check=full --trace-children=yes \
--show-leak-kinds=definite,indirect,possible --track-fds=yes \
--error-exitcode=1 --track-origins=yes \
../sentinel-minipot -s $socket_arg $minipot_arg
