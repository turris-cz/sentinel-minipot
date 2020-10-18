#!/bin/bash

test_type="$1"
minipot_type="$2"

case "$test_type" in
	"m")
		test_mesg="manual"
		case "$minipot_type" in
			"f")
				minipot_mesg="ftp"
				socket_arg="ipc:///tmp/sentinel_pull1.sock"
				minipot_arg="-F 9001"
				;;
			"h")
				minipot_mesg="http"
				socket_arg="ipc:///tmp/sentinel_pull2.sock"
				minipot_arg="-H 9002"
				;;
			"s")
				minipot_mesg="smtp"
				socket_arg="ipc:///tmp/sentinel_pull3.sock"
				minipot_arg="-S 9003"
				;;
			"t")
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
	"i")
		test_mesg="integration"
		case "$minipot_type" in
			"f")
				minipot_mesg="ftp"
				socket_arg="ipc:///tmp/sentinel_pull5.sock"
				minipot_arg="-F 9005"
				;;
			"h")
				minipot_mesg="http"
				socket_arg="ipc:///tmp/sentinel_pull6.sock"
				minipot_arg="-H 9006"
				;;
			"s")
				minipot_mesg="smtp"
				socket_arg="ipc:///tmp/sentinel_pull7.sock"
				minipot_arg="-S 9007"
				;;
			"t")
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
../sentinel-minipot -s "$socket_arg" "$minipot_arg"
