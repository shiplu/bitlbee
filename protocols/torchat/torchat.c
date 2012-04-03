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

#define ARRAY_SIZE(x) (sizeof(x)/sizeof(x[0]))

struct torchat_data {
	struct im_connection *ic;
	/* The onion ID of the current account */
	char* id;
	/* The effective file descriptor. We store it here so any function can
	 * write() to it. */
	int fd;
	/* File descriptor returned by bitlbee. we store it so we know when
	 * we're connected and when we aren't. */
	int bfd;
	/* ssl_getfd() uses this to get the file descriptor. */
	void *ssl;
	/* Same for file transfers. */
	int filetransfer_status;
};

struct torchat_buddy_data {
	struct {
		char *name;
		char *version;
	} client;
};

typedef void (*torchat_parser)(struct im_connection *ic, char *address, char *line);

static gboolean torchat_valid_address (char* test)
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

static int torchat_write(struct im_connection *ic, char *buf, int len)
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

static int torchat_printf(struct im_connection *ic, char *fmt, ...)
{
	va_list args;
	char* str;
	int st;

	va_start(args, fmt);
	g_vasprintf(&str, fmt, args);
	va_end(args);

	st = torchat_write(ic, str, strlen(str));

	g_free(str);

	return st;
}

static void torchat_parse_authorized(struct im_connection *ic, char *address, char* line)
{
	struct torchat_data *td = ic->proto_data;
	account_t *acc = ic->acc;

	if (line && *line) {
		if (td->id) {
			if (strcmp(td->id, line)) {
				g_free(td->id);

				td->id = g_strdup(line);
			}
		} else {
			td->id = g_strdup(line);
		}

		set_setstr(&acc->set, "id", td->id);
	}

	imcb_connected(ic);
}

static void torchat_parse_connected(struct im_connection *ic, char *address, char* line)
{
	imcb_add_buddy(ic, address, NULL);
	imcb_buddy_status(ic, address, BEE_USER_ONLINE, NULL, NULL);
}

static void torchat_parse_disconnected(struct im_connection *ic, char *address, char* line)
{
	if (!bee_user_by_handle(ic->bee, ic, address))
		return;

	imcb_buddy_status(ic, address, 0, NULL, NULL);
}

static void torchat_parse_remove(struct im_connection *ic, char *address, char *line)
{
	imcb_remove_buddy(ic, address, NULL);
}

static void torchat_parse_status(struct im_connection *ic, char *address, char* line)
{
	if (!strcmp(line, "available"))
		imcb_buddy_status(ic, address, BEE_USER_ONLINE, NULL, NULL);
	else if (!strcmp(line, "away") || !strcmp(line, "xa"))
		imcb_buddy_status(ic, address, BEE_USER_ONLINE | BEE_USER_AWAY, NULL, NULL);
	else if (!strcmp(line, "offline"))
		imcb_buddy_status(ic, address, 0, NULL, NULL);
}

static void torchat_parse_client_name(struct im_connection *ic, char *address, char* line)
{
	bee_user_t *bu = bee_user_by_handle(ic->bee, ic, address);
	struct torchat_buddy_data *bd = bu->data;

	if (bd->client.name) {
		g_free(bd->client.name);
	}

	bd->client.name = g_strdup(line);
}

static void torchat_parse_client_version(struct im_connection *ic, char *address, char* line)
{
	bee_user_t *bu = bee_user_by_handle(ic->bee, ic, address);
	struct torchat_buddy_data *bd = bu->data;

	if (bd->client.version) {
		g_free(bd->client.version);
	}

	bd->client.version = g_strdup(line);
}

static void torchat_parse_name(struct im_connection *ic, char *address, char* line)
{
	if (strlen(line) > 0)
		imcb_rename_buddy(ic, address, line);
	else
		imcb_rename_buddy(ic, address, NULL);
}

static void torchat_parse_description(struct im_connection *ic, char *address, char* line)
{
	if (strlen(line) > 0)
		imcb_buddy_status_msg(ic, address, line);
	else
		imcb_buddy_status_msg(ic, address, NULL);
}

static void torchat_parse_list(struct im_connection *ic, char *address, char* line)
{
	char **ids, **idptr, *id;

	idptr = ids = g_strsplit(line, " ", 0);

	while ((id = *idptr++) && strlen(id)) {
		imcb_add_buddy(ic, id, NULL);

		torchat_printf(ic, "STATUS %s\n", id);
		torchat_printf(ic, "CLIENT %s\n", id);
		torchat_printf(ic, "NAME %s\n", id);
		torchat_printf(ic, "DESCRIPTION %s\n", id);
	}

	g_strfreev(ids);
}

static void torchat_parse_message(struct im_connection *ic, char *address, char* line)
{
	imcb_buddy_msg(ic, address, line, 0, 0);
}

static gboolean torchat_read_callback(gpointer data, gint fd, b_input_condition cond)
{
	struct im_connection *ic = data;
	struct torchat_data *td = ic->proto_data;
	char buf[1024];
	int st, i;
	char **lines, **lineptr, *line, *tmp, *address;
	static struct parse_map {
		char *k;
		torchat_parser v;
	} parsers[] = {
		{ "AUTHORIZED", torchat_parse_authorized },
		{ "CONNECTED", torchat_parse_connected },
		{ "DISCONNECTED", torchat_parse_disconnected },
		{ "REMOVE", torchat_parse_remove },
		{ "STATUS", torchat_parse_status },
		{ "CLIENT_NAME", torchat_parse_client_name },
		{ "CLIENT_VERSION", torchat_parse_client_version },
		{ "NAME", torchat_parse_name },
		{ "DESCRIPTION", torchat_parse_description },
		{ "LIST", torchat_parse_list },
		{ "MESSAGE", torchat_parse_message }
	};

	if (!td || !td->ssl || td->fd == -1)
		return FALSE;

	/* Read the whole data. */
	st = ssl_read(td->ssl, buf, sizeof(buf));
	if (st > 0) {
		buf[st] = '\0';

		/* Then split it up to lines. */
		lineptr = lines = g_strsplit(buf, "\n", 0);

		while ((line = *lineptr++) && strlen(line)) {
			tmp = NULL;

			if (strchr(line, ' ') && torchat_valid_address(tmp = g_strndup(line, strchr(line, ' ') - line))) {
				address = tmp;
				line    = line + strlen(address) + 1;
			} else {
				address = NULL;
			}

			for (i = 0; i < ARRAY_SIZE(parsers); i++) {
				if (!strncmp(line, parsers[i].k, strlen(parsers[i].k))) {
					parsers[i].v(ic, address, line + strlen(parsers[i].k) + 1);
					break;
				}
			}

			if (tmp)
				g_free(tmp);
		}

		g_strfreev(lines);
	} else if (st == 0 || (st < 0 && !sockerr_again())) {
		closesocket(td->fd);
		td->fd = -1;

		imcb_error(ic, "Error while reading from server");
		imc_logout(ic, TRUE);

		return FALSE;
	}

	return TRUE;
}

static void torchat_buddy_data_add(bee_user_t *bu)
{
	bu->data = g_new0(struct torchat_buddy_data, 1);
}

static void torchat_buddy_data_free(bee_user_t *bu)
{
	struct torchat_buddy_data *bd = bu->data;

	if (bd->client.name)
		g_free(bd->client.name);

	if (bd->client.version)
		g_free(bd->client.version);

	g_free(bd);
}

static void *torchat_buddy_action(struct bee_user *bu, const char *action, char * const args[], void *data)
{
	struct torchat_buddy_data *bd = bu->data;

	if (!strcmp(action, "VERSION") && bd->client.name) {
		char *tmp = g_strdup_printf("%s %s", bd->client.name, bd->client.version);
		char * const argv[] = { tmp, NULL };

		imcb_buddy_action_response(bu, action, argv, NULL);

		g_free(tmp);
	}

	return NULL;
}

static void torchat_remove_buddy(struct im_connection *ic, char *who, char *group)
{
	torchat_printf(ic, "REMOVE %s\n", who);
}

static void torchat_add_buddy(struct im_connection *ic, char *who, char *group)
{
	torchat_printf(ic, "ADD %s\n", who);
}

static GList *torchat_away_states(struct im_connection *ic)
{
	static GList *l = NULL;

	if (l == NULL) {
		l = g_list_append(l, "away");
		l = g_list_append(l, "extended away");
	}

	return l;
}

static void torchat_set_away(struct im_connection *ic, char *state, char *message)
{
	if (state == NULL) {
		torchat_printf(ic, "STATUS available\n");
		torchat_printf(ic, "DESCRIPTION %s\n", message);
	}
	else {
		torchat_printf(ic, "STATUS %s\n", (!strcmp(state, "extended away")) ? "xa" : state);

		if (message)
			torchat_printf(ic, "DESCRIPTION %s\n", message);
	}
}

static void torchat_get_info(struct im_connection *ic, char *who)
{
	bee_user_t *bu = bee_user_by_handle(ic->bee, ic, who);
	struct torchat_buddy_data *bd = bu->data;

	if (bd->client.name)
		imcb_log(ic, "%s is using %s %s", who, bd->client.name, bd->client.version);

	if (bu->fullname)
		imcb_log(ic, "%s's name is `%s'", who, bu->fullname);

	if (bu->status_msg)
		imcb_log(ic, "%s's description is `%s'", who, bu->status_msg);
}

static int torchat_buddy_msg(struct im_connection *ic, char *who, char *message, int flags)
{
	return torchat_printf(ic, "MESSAGE %s %s\n", who, message);
}

static void torchat_logout(struct im_connection *ic)
{
	struct torchat_data *td = ic->proto_data;

	torchat_printf(ic, "STATUS offline\n");

	g_free(td);
	
	if (td->id)
		g_free(td->id);

	ic->proto_data = NULL;
}

static gboolean torchat_start_stream(struct im_connection *ic)
{
	struct torchat_data *td = ic->proto_data;

	if (!td)
		return FALSE;

	if (td->bfd <= 0)
		td->bfd = b_input_add(td->fd, B_EV_IO_READ, torchat_read_callback, ic);

	return torchat_printf(ic, "PASS %s\n", ic->acc->pass) &&
	       torchat_printf(ic, "STATUS available\n") &&
	       torchat_printf(ic, "LIST\n");
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

	torchat_printf(ic, "NAME %s\n", value);

	return value;
}

static void torchat_set_my_name(struct im_connection *ic, char *info)
{
	torchat_set_display_name(set_find(&ic->acc->set, "display_name"), info);
}

static char *torchat_dont_set(set_t *set, char *value)
{
	account_t *acc = set->data;
	struct im_connection *ic = acc->ic;
	struct torchat_data *td = ic->proto_data;

	return g_strdup(td->id);
}

static void torchat_init(account_t *acc)
{
	set_t *s;

	s = set_add(&acc->set, "server", TORCHAT_DEFAULT_SERVER, set_eval_account, acc);
	s->flags |= ACC_SET_OFFLINE_ONLY;

	s = set_add(&acc->set, "port", TORCHAT_DEFAULT_PORT, set_eval_int, acc);
	s->flags |= ACC_SET_OFFLINE_ONLY;

	s = set_add(&acc->set, "id", NULL, torchat_dont_set, acc);
	s->flags |= ACC_SET_NOSAVE;

	s = set_add(&acc->set, "display_name", NULL, torchat_set_display_name, acc);

	acc->flags |= ACC_FLAG_AWAY_MESSAGE | ACC_FLAG_STATUS_MESSAGE;
}

void init_plugin(void)
{
	struct prpl *ret = g_new0(struct prpl, 1);

	ret->name = "torchat";
	ret->login = torchat_login;
	ret->init = torchat_init;
	ret->logout = torchat_logout;
	ret->buddy_msg = torchat_buddy_msg;
	ret->handle_cmp = g_strcasecmp;
	ret->set_my_name = torchat_set_my_name;
	ret->away_states = torchat_away_states;
	ret->set_away = torchat_set_away;
	ret->get_info = torchat_get_info;
	ret->add_buddy = torchat_add_buddy;
	ret->remove_buddy = torchat_remove_buddy;
	ret->buddy_action = torchat_buddy_action;
	ret->buddy_data_add = torchat_buddy_data_add;
	ret->buddy_data_free = torchat_buddy_data_free;

	register_protocol(ret);
}
