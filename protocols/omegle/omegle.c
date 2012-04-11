/*
 *  omegle.c - Omegle plugin for BitlBee
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

#include <bitlbee.h>
#include <http_client.h>
#include <jansson.h>

struct omegle_data {
	struct im_connection *ic;

	gint main_loop_id;
};

struct omegle_buddy_data {
	char* host;
	char* session_id;
	gboolean checking;
	gboolean connecting;
	gboolean disconnecting;
	GSList *backlog;
};

static void omegle_http_dummy(struct http_request *req)
{
}

static void omegle_get(struct im_connection *ic, char *who, char *host, char *path, http_input_function callback)
{
	struct bee_user *bu = bee_user_by_handle(ic->bee, ic, who);
	GString *request;

	if (!bu)
		return;

	request = g_string_new("");

	g_string_append_printf(request, "GET %s HTTP/1.0\r\n", path);
	g_string_append_printf(request, "Host: %s\r\n", host);
	g_string_append_printf(request, "User-Agent: BitlBee " BITLBEE_VERSION " " ARCH "/" CPU "\r\n");
	g_string_append_printf(request, "\r\n");

	http_dorequest(host, 80, 0, request->str, callback, bu);

	g_string_free(request, TRUE);
}

static void omegle_post(struct im_connection *ic, char *who, char *path, char *data, http_input_function callback)
{
	struct bee_user *bu = bee_user_by_handle(ic->bee, ic, who);
	struct omegle_buddy_data *bd = bu->data;
	GString *request;
	GString *form;

	if (!bu)
		return;

	request = g_string_new("");
	form    = g_string_new("");

	g_string_append_printf(form, "id=%s&%s", bd->session_id, data);

	g_string_append_printf(request, "POST %s HTTP/1.0\r\n", path);
	g_string_append_printf(request, "Host: %s\r\n", bd->host);
	g_string_append_printf(request, "User-Agent: BitlBee " BITLBEE_VERSION " " ARCH "/" CPU "\r\n");
	g_string_append_printf(request, "Content-Type: application/x-www-form-urlencoded\r\n");
	g_string_append_printf(request, "Content-Length: %zd\r\n\r\n", form->len);
	g_string_append_printf(request, "%s", form->str);

	http_dorequest(bd->host, 80, 0, request->str, callback, bu);

	g_string_free(request, TRUE);
	g_string_free(form, TRUE);
}

static void omegle_send(struct im_connection *ic, char *who, char *path)
{
	omegle_post(ic, who, path, NULL, omegle_http_dummy);
}

static void omegle_send_with_callback(struct im_connection *ic, char *who, char *path, http_input_function callback)
{
	omegle_post(ic, who, path, NULL, callback);
}

static void omegle_send_message(struct im_connection *ic, char *who, char *message)
{
	GString *data = g_string_new("msg=");
	int i, length = strlen(message);

	for (i = 0; i < length; i++) {
		if (isalpha(message[i]) || isdigit(message[i]) ||
		    message[i] == '-' || message[i] == '_' || message[i] == '.' || message[i] == '!' ||
		    message[i] == '~' || message[i] == '*' || message[i] == '\'' || message[i] == '(' || message[i] == ')') {
			g_string_append_c(data, message[i]);
		} else if (message[i] == ' ') {
			g_string_append_c(data, '+');
		} else {
			g_string_append_printf(data, "%%%x", message[i]);
		}
	}

	omegle_post(ic, who, "/send", data->str, omegle_http_dummy);

	g_string_free(data, TRUE);
}

static int omegle_send_typing(struct im_connection *ic, char *who, int typing)
{
	struct bee_user *bu = bee_user_by_handle( ic->bee, ic, who );
	
	if (!(bu->flags & BEE_USER_ONLINE))
		return 0;

	if (typing & OPT_TYPING) {
		omegle_send(ic, who, "/typing");
	} else {
		omegle_send(ic, who, "/stoppedTyping");
	}

	return 1;
}

static void omegle_convo_got_id(struct http_request *req)
{
	struct bee_user *bu = req->data;
	struct omegle_buddy_data *bd = bu->data;

	bd->session_id = g_strndup(req->reply_body + 1, strlen(req->reply_body) - 2);
}

static void omegle_start_convo(struct im_connection *ic, char *who, char *host)
{
	struct bee_user *bu = bee_user_by_handle(ic->bee, ic, who);
	struct omegle_buddy_data *bd = bu->data;

	bd->host = host;

	omegle_get(ic, who, host, "/start", omegle_convo_got_id);
}

static void omegle_chose_server(struct http_request *req)
{
	struct bee_user *bu = req->data;
	struct omegle_buddy_data *bd = bu->data;
	struct im_connection *ic = bu->ic;
	char *who = bu->handle;
	json_error_t error;
	json_t *root = NULL;
	json_t *servers;
	int length, i;
	GRand* rand = NULL;

	if (!(root = json_loads(req->reply_body, 0, &error)))
		goto error;

	if (!(servers = json_object_get(root, "servers")))
		goto error;

	length = json_array_size(servers);
	rand = g_rand_new();
	i = g_rand_int_range(rand, 0, length);

	if (!(json_string_value(json_array_get(servers, i))))
		goto error;

	omegle_start_convo(ic, who, g_strdup(json_string_value(json_array_get(servers, i))));

	json_decref(root);
	g_rand_free(rand);

	return;

error:
	if (root) json_decref(root);
	if (rand) g_rand_free(rand);

	imcb_error(ic, "Could not fetch the server list, set one to use in the config");

	bd->connecting = FALSE;
}

static void omegle_disconnect_happened(struct im_connection *ic, char *who)
{
	struct bee_user *bu = bee_user_by_handle(ic->bee, ic, who);
	struct omegle_buddy_data *bd = bu->data;
	account_t *acc = ic->acc;

	if (set_getbool(&acc->set, "keep_online"))
		imcb_buddy_status(ic, who, BEE_USER_ONLINE | BEE_USER_AWAY, NULL, NULL);
	else
		imcb_buddy_status(ic, who, 0, NULL, NULL);

	if (bd->host) {
		g_free(bd->host);
		bd->host = NULL;
	}

	if (bd->session_id) {
		g_free(bd->session_id);
		bd->session_id = NULL;
	}

	if (bd->backlog) {
		g_slist_free_full(bd->backlog, g_free);
		bd->backlog = NULL;
	}

	bd->checking = FALSE;
	bd->connecting = FALSE;
	bd->disconnecting = FALSE;
}

static void omegle_disconnect_happened_http(struct http_request *req)
{
	struct bee_user *bu = req->data;

	omegle_disconnect_happened(bu->ic, bu->handle);
}

static void omegle_disconnect(struct im_connection *ic, char *who)
{
	struct bee_user *bu = bee_user_by_handle(ic->bee, ic, who);
	struct omegle_buddy_data *bd = bu->data;

	if (bd->disconnecting)
		return;

	bd->disconnecting = TRUE;

	omegle_send_with_callback(ic, who, "/disconnect", omegle_disconnect_happened_http);
}

static void omegle_add_deny(struct im_connection *ic, char *who)
{
}

static void omegle_rem_deny(struct im_connection *ic, char *who)
{
}

static void omegle_add_permit(struct im_connection *ic, char *who)
{
	struct bee_user *bu = bee_user_by_handle(ic->bee, ic, who);
	struct omegle_buddy_data *bd = bu->data;
	account_t *acc = ic->acc;
	char *host = set_getstr(&acc->set, "host");

	if (bd->connecting || bd->session_id)
		return;

	bd->connecting = TRUE;

	if (host) {
		omegle_start_convo(ic, who, g_strdup(host));
	}
	else {
		omegle_get(ic, who, "omegle.com", "/status", omegle_chose_server);
	}
}

static void omegle_rem_permit(struct im_connection *ic, char *who)
{
	omegle_disconnect(ic, who);
}

static void omegle_buddy_data_add(bee_user_t *bu)
{
	bu->data = g_new0(struct omegle_buddy_data, 1);
}

static void omegle_buddy_data_free(bee_user_t *bu)
{
	struct omegle_buddy_data *bd = bu->data;

	if (bd->host)
		g_free(bd->host);

	if (bd->session_id)
		g_free(bd->session_id);

	if (bd->backlog)
		g_slist_free_full(bd->backlog, g_free);

	g_free(bd);
}

static void omegle_remove_buddy(struct im_connection *ic, char *who, char *group)
{
	imcb_remove_buddy(ic, who, NULL);
}

static void omegle_add_buddy(struct im_connection *ic, char *who, char *group)
{
	account_t *acc = ic->acc;

	imcb_add_buddy(ic, who, NULL);

	if (set_getbool(&acc->set, "keep_online"))
		imcb_buddy_status(ic, who, BEE_USER_ONLINE | BEE_USER_AWAY, NULL, NULL);
}

static int omegle_buddy_msg(struct im_connection *ic, char *who, char *message, int flags)
{
	struct bee_user *bu = bee_user_by_handle(ic->bee, ic, who);
	struct omegle_buddy_data *bd = bu->data;

	if (!bd->session_id) {
		bd->backlog = g_slist_append(bd->backlog, g_strdup(message));

		omegle_add_permit(ic, who);
	} else {
		omegle_send_message(ic, who, message);
	}

	return 1;
}

static void omegle_logout(struct im_connection *ic)
{
	struct omegle_data *od = ic->proto_data;

	if (od)
		g_free(od);
	
	ic->proto_data = NULL;
}

static void omegle_init(account_t *acc)
{
	set_t *s;

	s = set_add(&acc->set, "host", NULL, set_eval_account, acc);

	s = set_add(&acc->set, "fetch_interval", "2", set_eval_int, acc);
	s->flags |= ACC_SET_OFFLINE_ONLY;

	s = set_add(&acc->set, "keep_online", "false", set_eval_bool, acc);

	s = set_add(&acc->set, "auto_add_strangers", "1", set_eval_int, acc);
	s->flags |= ACC_SET_OFFLINE_ONLY;

	s = set_add(&acc->set, "stranger_prefix", "Stranger", set_eval_account, acc);
	s->flags |= ACC_SET_OFFLINE_ONLY;
}

static void omegle_handle_events(struct http_request *req)
{
	struct bee_user *bu = req->data;
	struct omegle_buddy_data *bd = bu->data;
	struct im_connection *ic = bu->ic;
	json_error_t error;
	json_t *root;
	int length, i;
	const char *name;
	GSList *l;

	if (bd->disconnecting)
		return;

	if (req->status_code != 200) {
		imcb_error(ic, "Got an HTTP error: %d", req->status_code);

		omegle_disconnect_happened(ic, bu->handle);

		return;
	}

	if (!(root = json_loads(req->reply_body, JSON_DECODE_ANY, &error))) {
		imcb_error(ic, "Could not parse JSON: %s", error.text);
		imcb_error(ic, "at %d:%d in:", error.line, error.column);
		imcb_error(ic, "%s", req->reply_body);

		bd->checking = FALSE;

		return;
	}

	if (!json_is_array(root))
		return;

	for (i = 0, length = json_array_size(root); i < length; i++) {
		name = json_string_value(json_array_get(json_array_get(root, i), 0));

		if (!strcmp(name, "connected")) {
			imcb_buddy_status(ic, bu->handle, BEE_USER_ONLINE, NULL, NULL);

			for (l = bd->backlog; l; l = l->next) {
				omegle_send_message(ic, bu->handle, l->data);
			}

			g_slist_free_full(bd->backlog, g_free);

			bd->connecting = FALSE;
			bd->backlog = NULL;
		} else if (!strcmp(name, "typing")) {
			imcb_buddy_typing(ic, bu->handle, OPT_TYPING);
		} else if (!strcmp(name, "stoppedTyping")) {
			imcb_buddy_typing(ic, bu->handle, 0);
		} else if (!strcmp(name, "gotMessage")) {
			imcb_buddy_typing(ic, bu->handle, 0);
			imcb_buddy_msg(ic, bu->handle, (char*) json_string_value(json_array_get(json_array_get(root, i), 1)), 0, 0);
		} else if (!strcmp(name, "strangerDisconnected")) {
			omegle_disconnect_happened(ic, bu->handle);

			break;
		}
	}

	bd->checking = FALSE;

	json_decref(root);
}

gboolean omegle_main_loop(gpointer data, gint fd, b_input_condition cond)
{
	struct im_connection *ic = data;
	account_t *acc = ic->acc;
	struct bee_user *bu;
	struct omegle_buddy_data *bd;
	int number, i;
	char *name, *prefix;
	GSList *l;

	if (!(ic->flags & OPT_LOGGED_IN)) {
		imcb_connected(ic);

		prefix = set_getstr(&acc->set, "stranger_prefix");
		number = set_getint(&acc->set, "auto_add_strangers");

		for (i = 0; i < number; i++) {
			if (i == 0)
				name = g_strdup(prefix);
			else
				name = g_strdup_printf("%s%d", prefix, i);

			imcb_add_buddy(ic, name, NULL);

			if (set_getbool(&acc->set, "keep_online"))
				imcb_buddy_status(ic, name, BEE_USER_ONLINE | BEE_USER_AWAY, NULL, NULL);

			g_free(name);
		}
	}

	for (l = ic->bee->users; l; l = l->next) {
		bu = l->data;
		bd = bu->data;

		if (bu->ic != ic || bd->checking || !bd->session_id || bd->disconnecting)
			continue;

		bd->checking = TRUE;

		omegle_send_with_callback(ic, bu->handle, "/events", omegle_handle_events);
	}

	// If we are still logged in run this function again after timeout.
	return (ic->flags & OPT_LOGGED_IN) == OPT_LOGGED_IN;
}

static void omegle_login(account_t *acc)
{
	struct im_connection *ic = imcb_new(acc);
	struct omegle_data *od = g_new0(struct omegle_data, 1);

	ic->proto_data = od;
	od->ic = ic;

	od->main_loop_id = b_timeout_add(set_getint(&ic->acc->set, "fetch_interval") * 1000, omegle_main_loop, ic);
}

void init_plugin(void)
{
	struct prpl *ret = g_new0(struct prpl, 1);

	ret->name = "omegle";
	ret->login = omegle_login;
	ret->init = omegle_init;
	ret->logout = omegle_logout;
	ret->buddy_msg = omegle_buddy_msg;
	ret->handle_cmp = g_strcasecmp;
	ret->add_buddy = omegle_add_buddy;
	ret->remove_buddy = omegle_remove_buddy;
	ret->buddy_data_add = omegle_buddy_data_add;
	ret->buddy_data_free = omegle_buddy_data_free;
	ret->add_permit = omegle_add_permit;
	ret->rem_permit = omegle_rem_permit;
	ret->add_deny = omegle_add_deny;
	ret->rem_deny = omegle_rem_deny;
	ret->send_typing = omegle_send_typing;

	register_protocol(ret);
}
