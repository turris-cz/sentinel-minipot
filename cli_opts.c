/*
 *  Turris:Sentinel Minipot - password Honeypot
 *  Copyright (C) 2019-2020 CZ.NIC z.s.p.o. (https://www.nic.cz/)
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <argp.h>

#include "minipot_config.h"

#define ARGP_ERROR_PORT_OUT_RAN -1

const char *argp_program_version = PACKAGE_NAME " " PACKAGE_VERSION;
const char *argp_program_bug_address = "<packaging@turris.cz>";
static const char doc[] =
	"Turris Sentinel Minipot - minimal honeypot\n"
	"It collects authentication data by emulating various network aplication services.";
static struct argp_option options[] = {
	{"user", 'u', "USER", 0, "User to drop priviledges", 0},
	{"topic", 't', "TOPIC", 0, "Topic for communication with proxy", 0},
	{"telnet", 'T', "TELNET_PORT", 0, "Port for Telnet minipot", 0},
	{"socket", 's', "SOCKET", 0, "Local socket for interprocess communication", 0},
	{"http", 'H', "HTTP_PORT", 0, "Port for HTTP minipot", 0},
	{"ftp", 'F', "FTP_PORT", 0, "Port for FTP minipot", 0},
	{"smtp", 'S', "SMTP_PORT", 0, "Port for SMTP minipot", 0},
	{0},
};

static int parse_port(uint16_t *port, char *str) {
	char *end_ptr;
	errno = 0;
	long int result = strtol(str, &end_ptr, 10);
	if ((errno == ERANGE && (result == LONG_MAX || result == LONG_MIN)) || // port value out of range of long int
		(result == 0 && errno != 0) || // another conversion error
		(result < 0 || result > 65535) || // port out of range
		end_ptr == str) // no digits
		return -1;
	else
		*port = result;
		return 0;
}

static error_t parse_opt(int key, char *arg, struct argp_state *state) {
	struct configuration *conf = state->input;
	enum minipot_type new_minipot_type = MP_TYPE_NUM_TYPES; // In default not minipot
	switch (key) {
		case 'u':
			conf->user = arg;
			break;
		case 't':
			conf->topic = arg;
			break;
		case 's':
			conf->socket = arg;
			break;
		case 'T':
			new_minipot_type = MP_TYPE_TELNET;
			break;
		case 'H':
			new_minipot_type = MP_TYPE_HTTP;
			break;
		case 'F':
			new_minipot_type = MP_TYPE_FTP;
			break;
		case 'S':
			new_minipot_type = MP_TYPE_SMTP;
			break;
		default:
			return ARGP_ERR_UNKNOWN;
	}
	if (new_minipot_type < MP_TYPE_NUM_TYPES) {
		if (conf->minipots_count < MAX_MINIPOT_COUNT) {
			if (parse_port(&conf->minipots_conf[conf->minipots_count].port, arg))
				return ARGP_ERROR_PORT_OUT_RAN;
			conf->minipots_conf[conf->minipots_count].type = new_minipot_type;
			conf->minipots_count++;
		} else
			fprintf(stderr, "Maximal minipot count reached! Minipot ignored!\n"); \
	}
	return 0;
}

int load_cli_opts(int argc, char **argv, struct configuration *conf ) {
	struct argp arg_parser = {options, parse_opt, 0, doc, 0, 0, 0};
	error_t err = argp_parse(&arg_parser, argc, argv, 0 , 0, conf);
	if (err == ARGP_ERR_UNKNOWN) {
		fprintf(stderr, "Error - argp unknown error\n");
		return -1;
	} else if (err == ARGP_ERROR_PORT_OUT_RAN) {
		fprintf(stderr, "Error - port must be 0-65535!\n");
		return -1;
	} else if (conf->minipots_count < 1) {
		fprintf(stderr, "At least one minipot must be defined!\n");
		argp_help(&arg_parser, stdout, ARGP_HELP_USAGE, PACKAGE_NAME);
		return -1;
	}
	return 0;
}
