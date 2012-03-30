/*
 *  torchat.c - TorChat plugin for BitlBee
 *
 *  Copyright (c) 2012 by meh. <meh@paranoici.org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307,
 *  USA.
 */

/*
 *  Some code taken from: skype.c - Skype plugin for BitlBee
 *
 *  Copyright (c) 2007, 2008, 2009, 2010, 2011, 2012 by Miklos Vajna <vmiklos@frugalware.org>
 */

#include <poll.h>
#include <stdio.h>
#include <bitlbee.h>
#include <ssl_client.h>
#include <glib/gprintf.h>

#define TORCHAT_DEFAULT_SERVER "localhost"
#define TORCHAT_DEFAULT_PORT   "11110"

#define IRC_LINE_SIZE 1024
#define ARRAY_SIZE(x) (sizeof(x)/sizeof(x[0]))

struct torchat_data {
	struct im_connection *ic;
	char *username;
	/* The effective file descriptor. We store it here so any function can
	 * write() to it. */
	int fd;
	/* File descriptor returned by bitlbee. we store it so we know when
	 * we're connected and when we aren't. */
	int bfd;
	/* ssl_getfd() uses this to get the file desciptor. */
	void *ssl;
	/* Same for file transfers. */
	int filetransfer_status;
};

gboolean torchat_valid_address (char* test)
{
	size_t length = strlen(test);
	size_t i;

	// it's either just the id or the id + .onion
	if (length != 16 && length != 22)
		return FALSE;

	if (length == 22 && strcmp(test + 16, ".onion"))
		return FALSE;

	for (i = 0; i < length; i++)
		if (!isalpha(test[i]) && !(isdigit(test[i]) && test[i] != '0' && test[i] != '1' && test[i] != '8' && test[i] != '9'))
			return FALSE;

	return TRUE;
}

int torchat_write(struct im_connection *ic, char *buf, int len)
{
	struct torchat_data *td = ic->proto_data;
	struct pollfd pfd[1];

	if (!td->ssl)
		return FALSE;

	pfd[0].fd = td->fd;
	pfd[0].events = POLLOUT;

	/* This poll is necessary or we'll get a SIGPIPE when we write() to
	 * td->fd. */
	poll(pfd, 1, 1000);
	if (pfd[0].revents & POLLHUP) {
		imc_logout(ic, TRUE);
		return FALSE;
	}
	ssl_write(td->ssl, buf, len);

	return TRUE;
}

int torchat_printf(struct im_connection *ic, char *fmt, ...)
{
	va_list args;
	char** str;
	int st;

	va_start(args, fmt);
	g_vasprintf(str, fmt, args);
	va_end(args);

	st = torchat_write(ic, *str, strlen(*str));

	g_free(*str);

	return st;
}

typedef void (*torchat_parser)(struct im_connection *ic, char* address, char *line);

static void torchat_parse_connected(struct im_connection *ic, char* address, char* line)
{

}

static void torchat_parse_disconnected(struct im_connection *ic, char* address, char* line)
{

}

static void torchat_parse_status(struct im_connection *ic, char* address, char* line)
{

}

static void torchat_parse_client(struct im_connection *ic, char* address, char* line)
{

}

static void torchat_parse_name(struct im_connection *ic, char* address, char* line)
{

}

static void torchat_parse_description(struct im_connection *ic, char* address, char* line)
{

}

static void torchat_parse_list(struct im_connection *ic, char* address, char* line)
{

}

static gboolean torchat_read_callback(gpointer data, gint fd, b_input_condition cond)
{
	struct im_connection *ic = data;
	struct torchat_data *td = ic->proto_data;
	char* buf = NULL;
	int st, i, times = 1, current = 0;
	char **lines, **lineptr, *line, *tmp, *address;
	static struct parse_map {
		char *k;
		torchat_parser v;
	} parsers[] = {
		{ "CONNECTED", torchat_parse_connected },
		{ "DISCONNECTED", torchat_parse_disconnected },
		{ "STATUS", torchat_parse_status },
		{ "CLIENT", torchat_parse_client },
		{ "NAME", torchat_parse_name },
		{ "DESCRIPTION", torchat_parse_description },
		{ "LIST", torchat_parse_list }
	};

	if (!td || td->fd == -1)
		return FALSE;

	buf = g_realloc(buf, times * 512);

	/* Read the whole data. */
	st = ssl_read(td->ssl, buf, sizeof(buf));
	if (st > 0) {
		current += st;
		buf[current] = '\0';

		do {
			buf = g_realloc(buf, times * 512);
			times++;

			st = ssl_read(td->ssl, buf + current, times * 512 - current);

			if (st < 0 && !sockerr_again()) {
				goto error;
			}

			current += st;
			buf[current] = '\0';
		} while (st > 0);

		/* Then split it up to lines. */
		lines = g_strsplit(buf, "\n", 0);
		lineptr = lines;

		while ((line = *lineptr)) {
			if (!strlen(line))
				break;

			if (torchat_valid_address(tmp = g_strndup(line, strchr(line, ' ') - line))) {
				address = tmp;
				line    = line + strlen(address) + 1;
			} else {
				address = NULL;
			}

			for (i = 0; i < ARRAY_SIZE(parsers); i++) {
				if (!strncmp(line, parsers[i].k, strlen(parsers[i].k))) {
					parsers[i].v(ic, address, line);
					break;
				}
			}

			g_free(tmp);

			lineptr++;
		}

		g_strfreev(lines);
	} else if (st == 0 || (st < 0 && !sockerr_again())) {
		goto error;
	}

end:
	g_free(buf);

	return TRUE;

error:
	g_free(buf);

	closesocket(td->fd);
	td->fd = -1;

	imcb_error(ic, "Error while reading from server");
	imc_logout(ic, TRUE);

	return FALSE;
}

static gboolean torchat_start_stream(struct im_connection *ic)
{
	struct torchat_data *td = ic->proto_data;
	int st;

	if (!td)
		return FALSE;

	if (td->bfd <= 0)
		td->bfd = b_input_add(td->fd, B_EV_IO_READ, torchat_read_callback, ic);

	st = torchat_printf(ic, "LIST\n");

	return st;
}

static gboolean torchat_connected_ssl(gpointer data, int returncode, void *source, b_input_condition cond)
{
	struct im_connection *ic = data;
	struct torchat_data *td = ic->proto_data;

	if (!source) {
		td->ssl = NULL;
		imcb_error(ic, "Could not connect to server");
		imc_logout(ic, TRUE);
		return FALSE;
	}

	imcb_log(ic, "Connected to server, logging in");

	return torchat_start_stream(ic);
}

static gboolean torchat_connected(gpointer data, gint fd, b_input_condition cond)
{
	struct im_connection *ic = data;
	struct torchat_data *td = ic->proto_data;
	account_t *acc = ic->acc;

	write(fd, "STARTTLS\n", 9);
	td->ssl = ssl_starttls(fd, set_getstr(&acc->set, "server"), FALSE, torchat_connected_ssl, ic);

	return TRUE;
}

static void torchat_login(account_t *acc)
{
	struct im_connection *ic = imcb_new(acc);
	struct torchat_data *td = g_new0(struct torchat_data, 1);

	ic->proto_data = td;

	imcb_log(ic, "Connecting");
	td->fd = proxy_connect(set_getstr(&acc->set, "server"), set_getint(&acc->set, "port"), torchat_connected, ic);

	td->ic = ic;
}

static char *torchat_set_display_name(set_t *set, char *value)
{
	account_t *acc = set->data;
	struct im_connection *ic = acc->ic;

	torchat_printf(ic, "NAME %s", value);

	return value;
}

static char *torchat_set_description(set_t *set, char *value)
{
	account_t *acc = set->data;
	struct im_connection *ic = acc->ic;

	torchat_printf(ic, "DESCRIPTION %s", value);

	return value;
}

static void torchat_init(account_t *acc)
{
	set_t *s;

	s = set_add(&acc->set, "server", TORCHAT_DEFAULT_SERVER, set_eval_account, acc);
	s->flags |= ACC_SET_OFFLINE_ONLY;

	s = set_add(&acc->set, "port", TORCHAT_DEFAULT_PORT, set_eval_int, acc);
	s->flags |= ACC_SET_OFFLINE_ONLY;

	s = set_add(&acc->set, "display_name", NULL, torchat_set_display_name, acc);
	s->flags |= ACC_SET_NOSAVE | ACC_SET_ONLINE_ONLY;

	s = set_add(&acc->set, "description", NULL, torchat_set_description, acc);
	s->flags |= ACC_SET_NOSAVE | ACC_SET_ONLINE_ONLY;
}

void init_plugin()
{
	struct prpl *ret = g_new0(struct prpl, 1);

	ret->name = "torchat";
	ret->login = torchat_login;

	register_protocol(ret);
}
