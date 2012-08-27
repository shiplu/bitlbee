/********************************************************************\
* BitlBee -- An IRC to other IM-networks gateway                     *
*                                                                    *
* Copyright 2002-2006 Wilmer van der Gaast and others                *
\********************************************************************/

/*
 * Storage backend that uses an MySQL.
 * Sample schema can be found on /doc/schema_mysql.sql
 */

/*
  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License with
  the Debian GNU/Linux distribution in /usr/share/common-licenses/GPL;
  if not, write to the Free Software Foundation, Inc., 59 Temple Place,
  Suite 330, Boston, MA  02111-1307  USA
*/

#define BITLBEE_CORE
#include "bitlbee.h"
#include "protocols/bee.h"
#include "base64.h"
#include "arc.h"
#include "sha1.h"
#include <mysql/mysql.h>

#include <mysql.h>
#include <glib/gstdio.h>
#include <glib.h>

#if GLIB_CHECK_VERSION(2,8,0)
#include <glib/gstdio.h>
#else
/* GLib < 2.8.0 doesn't have g_access, so just use the system access(). */
#include <unistd.h>
#define g_access access
#endif

typedef enum
{
    MYSQL_PASS_CHECK_ONLY = -1,
    MYSQL_PASS_UNKNOWN = 0,
    MYSQL_PASS_WRONG,
    MYSQL_PASS_OK
} mysql_pass_st;


/* To make it easier later when extending the format: */
#define MYSQL_FORMAT_VERSION 1

/* Function prototypes. Declared here so I dont have to scroll the whole file */
static void append_mysql_escaped_param(GString *query, GString *buffer, GString *param);
static void mysql_storage_init( void );
static void mysql_storage_deinit( void );
static storage_status_t mysql_storage_load( irc_t *irc, const char *password );
static storage_status_t mysql_storage_check_pass( const char *my_nick, const char *password );
static storage_status_t mysql_storage_save( irc_t *irc, int overwrite );
static storage_status_t mysql_storage_remove( const char *nick, const char *password );

/* Utility/Helper functions */
/** Function prototypes. Declared here so I dont have to scroll the whole file */
static void mysql_storage_save_nick(gpointer key, gpointer value, gpointer data);
static void append_mysql_escaped_param(GString *query, GString *buffer, GString *param);
static char* ret_mysql_esc_str(MYSQL *mysql, GString *buffer, GString *param);
static storage_status_t save_kv_pair(GString *q, GString *buf, char *table_name, 
		  char *fk_column_name, char *key_name, char *value_name, 
		  long fk_column_value, char *key, char *value);
static int send_query(MYSQL *mysql, const char *query, unsigned long len);
static GList * mysql_multiple_rows(MYSQL *mysql_handle, char* query);
static void mysql_free_multiple_rows(GList *table);
static void mysql_free_single_row(gpointer data);
static GSList* mysql_copy_single_row(MYSQL_RES *result);
static long storage_get_user_id(GString *q, GString *buf, GString *nick);

typedef struct database_object_t {
    MYSQL *mysql;
    GString *query_string;
    GString *string_buffer;
    gpointer data;
}database_object;

MYSQL *mysql = NULL;

/**
 * A wrapper for mysql query. 
 */
static int send_query(MYSQL *mysql, const char *query, unsigned long len){
    int return_value = 0, ping = 0; 
    unsigned int m_errno = 0;
    char *info = NULL;
    
    
    // checks if mysql is timed out
    ping = mysql_ping(mysql);
    
    return_value = mysql_real_query(mysql, query, len);
    m_errno = mysql_errno(mysql);
    info = mysql_info(mysql);
    
    
    //fprintf(stderr, "\tLength: %03lu  Errno: %u %s\n", len, m_errno, ((info==NULL)? "":info));
    if(m_errno!=0)
	fprintf(stderr, "\e[31mERROR\t%s\e[0m\n", mysql_error(mysql));
    
    return return_value;
}

/**
 * Escapes param and then append to query. Uses buffer for temporary storage;
 */
static void append_mysql_escaped_param(GString *query, GString *buffer, GString *param){
    g_string_set_size(buffer, param->len*2+1);
    mysql_real_escape_string(mysql, buffer->str, param->str, param->len);
    g_string_append(query, buffer->str);
}

static char* ret_mysql_esc_str(MYSQL *mysql, GString *buffer, GString *param){
    /// re-initializing the buffer.
    g_string_set_size(buffer, param->len*2+1);
    g_string_printf(buffer,"%s", "");
    mysql_real_escape_string(mysql, buffer->str, param->str, param->len);
    return buffer->str;
}

static void free_g_str_list(int num, ...){
    va_list arguments;
    GString *gs=NULL;
    va_start ( arguments, num );
    int i;
    for(i=0; i<num; i++){
        gs = va_arg(arguments, GString*);
	g_string_free(gs, TRUE);
    }
    va_end ( arguments );                  // Cleans up the list
}

/**
 * @param data as GSList with to element. first one is key. second one is value.
 * @param user_data The address of the set linked lists head element.
 */
static void mysql_storage_load_settings(gpointer data, gpointer user_data){
    GSList *row = data;
    /// save this set settings to irc user settings
    set_setstr(((set_t **)user_data), ((GString *)(row->data))->str, ((GString *)(row->next->data))->str);
}

static void mysql_storage_load_channels(gpointer data, gpointer user_data){
    char *name, *type;
    long int channel_id=0, user_id = 0;
    irc_t **ptr_irc= user_data;
    irc_t *irc = *ptr_irc;
    irc_channel_t *channel = NULL;
    GSList *row = data;
    GString *qry= NULL;
    GList *m_rows= NULL;
    
    /// get all the fields
    channel_id = atol(((GString *)row->data)->str);
    row = row->next;
    user_id = atol(((GString *)row->data)->str);
    row = row->next;
    name = g_strdup(((GString *)row->data)->str);
    row = row->next;
    type = g_strdup(((GString *)row->data)->str);

    //fprintf(stderr, "\tCurrent Channel: channel_id=%ld, user_id=%ld, name=%s, type=%s\n", channel_id, user_id,  name, type);
    
    if( !name || !type ){
        fprintf(stderr, "\e[31mERROR\tMissing values for channels. channel: %s type: %s\e[0m\n", name, type);
	g_free(name);
	g_free(type);
        return;
    }

    /// 4.2 Create/find a channel and assign
    channel = irc_channel_by_name( irc, name );
    if(!channel){
	fprintf(stderr, "\tNo IRC channel found. Creating one with name%s\n", name);
	channel =  irc_channel_new( irc, name );
    }
    
    if(channel){
	/// dont know why "type" is hardcoded here. 
	/// I just followed storage_xml.c
        set_setstr( &channel->set, "type", type );
    }else{
	g_free(name);
	g_free(type);
	fprintf(stderr, "\e[31mERROR\tLast channel creation was not successfull\e[0m\n");
	return;
    }
    
    /// 4.3 get all the chanel setting and update 1 by 1
    qry = g_string_new("SELECT name, value from channel_settings where channel=");
    g_string_append_printf(qry, "'%ld'", channel_id);
    m_rows = mysql_multiple_rows(mysql, qry->str);
    
    
    
    /// 3.3 Set all the user account settings to irc account struct 1 by 1
    g_list_foreach(m_rows, mysql_storage_load_settings, &channel->set);
    mysql_free_multiple_rows(m_rows);
    
    g_free(name);
    g_free(type);
    g_string_free(qry, TRUE);
}

static void mysql_storage_load_account_buddies(gpointer data, gpointer user_data){
    account_t **acc = user_data;
    account_t *account = *acc;
    GSList *row = data;
    /// there are two rows. So 2 iteration on fields
    char *handle = g_strdup(((GString *)(row->data))->str);
    char *nick = g_strdup(((GString *)(row->next->data))->str);
    if(account && handle && nick ){
        nick_set_raw(account, handle, nick );
    }else{
        fprintf(stderr, "\e[31mERROR\tMissing values for account buddy\e[0m\n");
    }
}

static void mysql_storage_load_account_settings(gpointer data, gpointer user_data){
    account_t **acc = user_data;
    account_t *account = *acc;
    GSList *row = data;
    /// there are two rows. So 2 iteration on fields
    char *name = g_strdup(((GString *)(row->data))->str);
    char *value = g_strdup(((GString *)(row->next->data))->str);
    
    if(account){
        set_t *s = set_find(&account->set, name);
        if( s && ( s->flags & ACC_SET_ONLINE_ONLY ) ){
            g_free(name);
	    /// not sure whether bellow statement will be needed.
	    //name = NULL;
            return;
        }
    }
    set_setstr(&account->set, name, (char*) value );
    g_free(name);
    
    /// not sure whether bellow statement will be needed.
    //name = NULL;
}

static void mysql_storage_load_accounts(gpointer data, gpointer user_data){
    GSList *row = data;
    GList *m_rows = NULL;
    account_t *acc = NULL;
    GString *qry = NULL;
    irc_t ** ptr_irc = user_data;
    irc_t *irc = *ptr_irc;
    char *protocol, *handle, *server, *password = NULL, *autoconnect, *tag;
//     int pass_len;
    long int account_id = 0/*, user_id=0*/;
    struct prpl *prpl = NULL;

    /**
    * This is the sequence how data is read
    * +-------------+
    * | id          |
    * | user        |
    * | protocol    |
    * | handle      |
    * | password    |
    * | autoconnect |
    * | tag         |
    * | server      |
    * +-------------+
    */
    
    account_id = atol(((GString *)row->data)->str);
    row = row->next;
    //user_id = atol(((GString *)row->data)->str);
    row = row->next;
    protocol = ((GString *)row->data)->str;
    row = row->next;
    handle = ((GString *)row->data)->str;
    row = row->next;
    password = ((GString *)row->data)->str;
    row = row->next;
    autoconnect = ((GString *)row->data)->str;
    row = row->next;
    tag = ((GString *)row->data)->str;
    row = row->next;
    server = ((GString *)row->data)->str;
    
    if( protocol )
        prpl = find_protocol( protocol );

    if( !handle || !password|| !protocol )
        fprintf(stderr, "\e[31mERROR\tMissing values for account\e[0m\n");
    else if( !prpl )
        fprintf(stderr, "\e[31mERROR\tUnknown protocol: %s\e[0m\n", protocol );
    else{
	//fprintf(stderr, "\e[31mERROR\tload/password: ['%s']\e[0m\n", password);
        acc = account_add(irc->b, prpl, handle, password );
        if( server )
            set_setstr( &acc->set, "server", server );
        if( autoconnect )
            set_setstr( &acc->set, "auto_connect", autoconnect );
        if( tag )
            set_setstr( &acc->set, "tag", tag );
    }
    //g_free( password );
    
    /// 3.2 Get all the settings 1 by 1
    qry = g_string_new("SELECT name, value from account_settings where account=");
    g_string_append_printf(qry, "'%ld'", account_id);
    m_rows = mysql_multiple_rows(mysql, qry->str);
    
    /// 3.3 Set all the user account settings to irc account struct 1 by 1
    g_list_foreach(m_rows, mysql_storage_load_account_settings, &acc);
    mysql_free_multiple_rows(m_rows);
    
    /// 3.4 Read all the renamed buddy
    g_string_printf(qry, "SELECT handle, nick from account_buddies where account='%ld'", account_id);
    m_rows = mysql_multiple_rows(mysql, qry->str);
    
    /// 3.5 Set all the renamed budy to irc account struct 1 by 1
    g_list_foreach(m_rows, mysql_storage_load_account_buddies, &acc);
    mysql_free_multiple_rows(m_rows);	
    
    g_string_free(qry, TRUE);
}


static void mysql_free_multiple_rows(GList *table){
    g_list_free_full(table, mysql_free_single_row);
}

/** 
 * Execute the query and returns all the result in a tabular format
 * You must free this table by caling mysql_free_multiple_rows
 */
static GList * mysql_multiple_rows(MYSQL *mysql_handle, char* query){
    my_ulonglong num_rows=0;
    MYSQL_RES *result = NULL;
    GSList *single_row = NULL;
    GList *rows = NULL;
    GString *q = g_string_new(query);
    int query_status = send_query(mysql_handle, q->str, q->len);

    if(query_status!=0){
	g_string_free(q, TRUE);
	return NULL;
    }
    
    result = mysql_store_result(mysql_handle);
    
    if(result==NULL){
	/// it was not a query that returns statemnet (e.g. INSERT, DELETE)
	g_string_free(q, TRUE);
	return NULL;
    }

    num_rows = mysql_num_rows(result);

    //fprintf(stderr, "\t%Ld row%s found\n", num_rows, ((num_rows==1)? "": "s"));
    
    if(num_rows>0){
	int i=0;
	for(i=0;i<num_rows; i++){
	    single_row = mysql_copy_single_row(result);
	    rows = g_list_prepend(rows, single_row);
	}
	/// As prepending list actually reverses it. We reverse it agian
	/// to get the correct order.
	rows = g_list_reverse(rows);
    }else{
	mysql_free_result(result);
	g_string_free(q, TRUE);
	return NULL;
    }
    
    /// clean up
    g_string_free(q, TRUE);
    mysql_free_result(result);
    return rows;
}

static void mysql_free_single_row_field(gpointer data){
    /// NULL fields in mysql are NULL. 
    /// Hence we check if its null
    g_string_free(data, TRUE);
}
static void mysql_free_single_row(gpointer data){
    g_slist_free_full(data, mysql_free_single_row_field);
}

static GSList* mysql_copy_single_row(MYSQL_RES *result) {
    GSList*  single_row=NULL;
    unsigned int num_fields = mysql_num_fields(result);
    int i=0;
    MYSQL_ROW row=mysql_fetch_row(result);
    
    for(i=num_fields-1; i>=0; i--) {
        GString *f = g_string_new(row[i]);
	single_row = g_slist_prepend(single_row, f);
    }
    
    return single_row;
}
/**
 * Excutes the passed query and returs the the first row as an array of 
 * strings. You must free this array by calling mysql_free_single_row()
 */
static GSList * mysql_single_row(MYSQL *mysql_handle, char* query){
    GList * rows = mysql_multiple_rows(mysql_handle, query);
    GSList *first_row = NULL;
    /// keep only the first row
    first_row = rows->data;
    /// clear the list but the elements
    g_list_free(rows);
    /// return back the row
    return first_row;
}
///@todo this function must be refactored along with set_settings_flag function. 
static storage_status_t set_channel_settings(MYSQL *mysql, set_t *settings, char * table_name, char *key_column_name, long key_column_id){
    GString *q = g_string_new("");
    GString *buf = g_string_new("");
    set_t *set;
    for( set = settings; set; set = set->next ) {
	if( set->value && (strcmp( set->key, "type" ) != 0)) {
	    if(save_kv_pair(q, buf, table_name, key_column_name, 
		"name", "value", key_column_id, set->key, set->value)!=STORAGE_OK){
		    g_string_free(q, TRUE);
		    g_string_free(buf, TRUE);
		    return STORAGE_OTHER_ERROR;
		}
	}
    }
    return STORAGE_OK;
}

static storage_status_t set_settings_flag(MYSQL *mysql, set_t *settings, char * table_name, char *key_column_name, long key_column_id, set_flags_t flag){
    GString *q = g_string_new("");
    GString *buf = g_string_new("");
    set_t *set;
    
    for( set = settings; set; set = set->next ) {
	if( set->value && !( set->flags & flag) ) {
		if(save_kv_pair(q, buf, table_name, key_column_name, 
		"name", "value", key_column_id, set->key, set->value)!=STORAGE_OK){
		    g_string_free(q, TRUE);
		    g_string_free(buf, TRUE);
		    return STORAGE_OTHER_ERROR;
		}
	}
    }
    return STORAGE_OK;
}


static void mysql_storage_init( void ) {
    mysql = mysql_init(NULL);
    my_bool reconnect = 1;
    mysql_options(mysql,MYSQL_OPT_RECONNECT, &reconnect);
    if (mysql == NULL) {
        fprintf(stderr, "\e[31mERROR\tCan not initialize MySQL. Configuration won't be saved.\e[0m\n");
    }
    if (!mysql_real_connect(mysql, global.conf->dbhost, global.conf->dbuser, global.conf->dbpass, NULL, global.conf->dbport, NULL, 0)) {
	fprintf(stderr, "\e[31mERROR\t%s\nConfiguration won't be saved.\e[0m\n", mysql_error(mysql));
    }

    // for some older version mysql_real_connect resets the reconnect option. So I set it again
    mysql_options(mysql,MYSQL_OPT_RECONNECT, &reconnect);
    
    if (mysql_select_db(mysql, global.conf->dbname)) {
        fprintf(stderr, "\e[31mERROR\t%s\nConfiguration won't be saved.\e[0m\n", mysql_error(mysql));
    }
}
static storage_status_t mysql_storage_load( irc_t *irc, const char *password ) {
    
//     GSList *row = NULL;
    GList *m_rows = NULL;
    GString *qry  = g_string_new("");
    GString *buf  = g_string_new("");
    GString *nick = g_string_new(irc->user->nick);
    
    long user_id =0;
    
    /// 1. Check if we have such user
    storage_status_t ss= mysql_storage_check_pass(irc->user->nick, password);
    
    /// if not found or something else we abort
    if(ss!=STORAGE_OK){
	free_g_str_list(3, buf, qry, nick);
	return ss;
    }
    
    /// 2. Read the user settings now
    /// 2.1 Get the user id.
    user_id = storage_get_user_id(qry, buf, nick);
    
    /// 2.2 Get all the settings 1 by 1
    g_string_printf(qry, "SELECT name, value from user_settings where user='%ld'", user_id);
    m_rows = mysql_multiple_rows(mysql, qry->str);
    
    /// 2.3 Set all the user settings to irc struct 1 by 1
    g_list_foreach(m_rows, mysql_storage_load_settings, &irc->b->set);
    mysql_free_multiple_rows(m_rows);
    
    /// 3. Get all the account current user have
    g_string_printf(qry, "SELECT id, user, protocol, handle, pass"
    "word, autoconnect, tag, server " /// <--- The space at the end is necessary
    "FROM `accounts` WHERE `user` = '%ld'", user_id);
    m_rows = mysql_multiple_rows(mysql, qry->str);
    
    if(g_list_length(m_rows)>0){
	/// 3.1. set all the accounts to this user
	/// This funciton also handles
	/// Setting all account settings and all the buddy list
	g_list_foreach(m_rows, mysql_storage_load_accounts, &irc);
	mysql_free_multiple_rows(m_rows);
    }else{
	fprintf(stderr, "\e[31m\tUser has no account!\e[0m");
    }
    
    /// 4. Get all the channels current user have
    g_string_printf(qry, "SELECT id, user, name, type "
    "FROM `channels` WHERE `user` = '%ld'", user_id);
    m_rows = mysql_multiple_rows(mysql, qry->str);
    
    if(g_list_length(m_rows)>0){
	/// 4.1 set all the channels info to this user
	g_list_foreach(m_rows, mysql_storage_load_channels, &irc);
	mysql_free_multiple_rows(m_rows);
    }else{
	fprintf(stderr, "\e[31m\tUser has no channel!\e[0m");
    }
    /// end clean up
    free_g_str_list(3, buf, qry, nick);
    return STORAGE_OK;
}


static storage_status_t mysql_storage_check_pass( const char *nick, const char *password ) {
    /// mysql variables
    MYSQL_RES *result;
    int ret_query=0;
    unsigned int field_count;
    my_ulonglong num_rows=0;
    
    /// return variable
    storage_status_t st = STORAGE_OTHER_ERROR;
    
    /// GString wrapper for string params 
    GString *g_nick = g_string_new(nick);
    GString *g_password = g_string_new(password);
    
    /// buffer to build query
    GString *to = g_string_new("");
    
    /// query string 
    GString *query = g_string_new("");
    
    /// building query
    /// @todo use a salt for password to increase security
    g_string_append(query, "SELECT id, nick, password, sha1('");
    append_mysql_escaped_param(query, to, g_password);
    g_string_append(query, "') from users where nick='");
    append_mysql_escaped_param(query, to, g_nick);
    g_string_append(query, "' limit 1");
    
    /// executing query
    ret_query = send_query(mysql,query->str,query->len);
    field_count = mysql_field_count(mysql);
    
    /// process query 
    if(ret_query==0){
	/// query is successfull
	if(field_count == 4){
	    result = mysql_store_result(mysql);
	    num_rows = mysql_num_rows(result);
	    
	    if(num_rows==1){
		MYSQL_ROW row;
		row = mysql_fetch_row(result);
		
		if(g_ascii_strncasecmp(row[2], row[3], strlen(row[2]))==0){
		    st = STORAGE_OK;
		}else{
		    st = STORAGE_INVALID_PASSWORD;
		}
	    }else{
		st = STORAGE_NO_SUCH_USER;
	    }
	    
	    /// clear up the result
	    mysql_free_result(result);
	}else{
	    st = STORAGE_NO_SUCH_USER;
	}
    }else{
	/// query is failed
	st = STORAGE_OTHER_ERROR;
    }

    /// free up GStrings used
    g_string_free(to, TRUE);
    g_string_free(g_nick, TRUE);
    g_string_free(g_password, TRUE);
    g_string_free(query, TRUE);
    
    return st;
}

static long storage_get_user_id(GString *q, GString *buf, GString *nick) {
    long int user_id;
    GSList *user_row = NULL;
    g_string_printf(q, "SELECT id from users where nick='");
    append_mysql_escaped_param(q, buf, nick);
    g_string_append(q,"'");
    user_row = mysql_single_row(mysql, q->str);
    user_id = atol(((GString *)user_row->data)->str);
    g_slist_free(user_row);
    return user_id;
}

static storage_status_t mysql_storage_save( irc_t *irc, int overwrite ) {
    /// static variables
    my_ulonglong num_rows=0;
    long user_id = 0;
  
    account_t *acc;
    storage_status_t settings_status;
    
    /// dynamic variables. Needs clean up function called
//     GSList *user_row = NULL;
//     GString *user_id_str = NULL;
    GString *nick = g_string_new(irc->user->nick);
    GString *pass = g_string_new(irc->password);
    GString *buf = g_string_new("");
    GString *q = g_string_new("INSERT INTO users (nick, password) values ('"); 
    
   
    /// 1. Save the user name
    append_mysql_escaped_param(q, buf, nick);
    g_string_append(q, "',sha1('");
    append_mysql_escaped_param(q, buf, pass);
    g_string_append(q, "')) ON DUPLICATE KEY UPDATE password = sha1('");
    append_mysql_escaped_param(q, buf, pass);
    g_string_append(q, "')");
    
    send_query(mysql, q->str, q->len);
    
    g_string_printf(q, "%s", "");
    
    num_rows = mysql_affected_rows(mysql);
    
    if(num_rows<0 || num_rows>2){
	fprintf(stderr, "User neither added, updated, unchanged\n");
	if(mysql_errno(mysql)!=0){
	    fprintf(stderr, "\e[31mERROR\t%s\e[0m\n", mysql_error(mysql));
	}
	g_string_free(nick, TRUE);
	g_string_free(pass, TRUE);
	g_string_free(buf, TRUE);
	g_string_free(q, TRUE);
	return STORAGE_OTHER_ERROR;
    }
    
    /// 2. Save the user settings
    ///   2.1 Get the user id
    user_id= storage_get_user_id(q, buf,nick);
    
    /// 2.2 Set all the settings 1 by 1
    settings_status = set_settings_flag(mysql, irc->b->set,"user_settings", "user", user_id, SET_NOSAVE);
	    
    if(settings_status!=STORAGE_OK){
	/// something bad happened!
	g_string_free(nick, TRUE);
	g_string_free(pass, TRUE);
	g_string_free(buf, TRUE);
	g_string_free(q, TRUE);
	return settings_status;
    }

    /// 3. Set all the user accounts
    /// 3.0. But first delete all the accounts
    g_string_printf(q, "DELETE FROM accounts WHERE `user` = '%lu'", user_id);
    
    send_query(mysql, q->str, q->len);
    
    for( acc = irc->b->accounts; acc; acc = acc->next ){
	//acc->prpl->name, acc->user, pass_b64, acc->auto_connect, acc->tag
	/// 3.1 add user accounts
	GString *acc_protocol = g_string_new(acc->prpl->name);
	GString *acc_handle = g_string_new(acc->user);
	GString *acc_password = g_string_new(acc->pass);
	GString *acc_tag = g_string_new(acc->tag);
	gboolean server_exists = (acc->server && acc->server[0]);
	GString *acc_server = NULL;
	GString *account_id_str = NULL;
	GSList *account_row = NULL;
	
	if(server_exists){
	    acc_server = g_string_new(acc->server);
	    g_string_printf(q, "INSERT INTO accounts (user, protocol, handle, password, autoconnect, tag, server) values (%ld, '", user_id);
	}
	else
	    g_string_printf(q, "INSERT INTO accounts (user, protocol, handle, password, autoconnect, tag) values (%ld, '", user_id);
	
	    
	append_mysql_escaped_param(q, buf, acc_protocol);
	g_string_append(q,"', '");
	append_mysql_escaped_param(q, buf, acc_handle);
	g_string_append(q,"', '");
	append_mysql_escaped_param(q, buf, acc_password);
	g_string_append_printf(q, "', '%d', '", acc->auto_connect);
	append_mysql_escaped_param(q, buf, acc_tag);
	
	if(server_exists){
	    g_string_append(q,"', '");
	    append_mysql_escaped_param(q, buf, acc_server);
	}
	
	g_string_append(q,"') on duplicate key UPDATE password='");
	append_mysql_escaped_param(q, buf, acc_password);
	g_string_append_printf(q,"', autoconnect='%d', tag='", acc->auto_connect);
	append_mysql_escaped_param(q, buf, acc_tag);
	
	if(server_exists){
	    g_string_append(q,"', server='");
	    append_mysql_escaped_param(q, buf, acc_server);
	}
	
	g_string_append(q,"'");
	
	if(server_exists){
	    g_string_free(acc_server, TRUE);
	}
	send_query(mysql, q->str, q->len);
	num_rows =  mysql_affected_rows(mysql);
	if(num_rows<0 || num_rows>2){
	    /// something went wrong.
	    g_string_free(acc_handle, TRUE);
	    g_string_free(acc_password, TRUE);
	    g_string_free(acc_protocol, TRUE);
	    g_string_free(acc_tag, TRUE);
	    g_string_free(account_id_str, TRUE);
	    g_string_free(nick, TRUE);
	    g_string_free(pass, TRUE);
	    g_string_free(buf, TRUE);
	    g_string_free(q, TRUE);
	    return STORAGE_OTHER_ERROR;
	}
	
	/// 3.2 add user account settings
	g_string_printf(q, "select id from accounts where user='%ld' and protocol='", user_id);
	append_mysql_escaped_param(q, buf, acc_protocol);
	g_string_append(q, "' and handle='");
	append_mysql_escaped_param(q, buf, acc_handle);
	g_string_append(q, "'");
	account_row = mysql_single_row(mysql, q->str);
	account_id_str = (GString *)account_row->data;
	settings_status = set_settings_flag(mysql, irc->b->set, "account_settings", "account", atol(account_id_str->str), ACC_SET_NOSAVE);
	    
	if(settings_status!=STORAGE_OK){
	    /// something bad happened!
	    free_g_str_list(8, acc_handle, acc_password, acc_protocol, acc_tag, account_id_str, nick, pass, buf, q);
	    mysql_free_single_row(account_row);
	    return settings_status;
	}
	
	/// 3.3 adding all the renamed buddies. 
	/// buddies you have renamed to good nicks.
	{
	    database_object dbo;
	    dbo.mysql = mysql;
	    dbo.query_string = q;
	    dbo.string_buffer = buf;
	    dbo.data = (gpointer)(account_id_str->str);
	    /// before that we delete all the buddies
	    g_string_printf(q, "DELETE FROM account_buddies WHERE `account` = '%lu'", atol(account_id_str->str));
	    send_query(mysql, q->str, q->len);
	    
	    g_hash_table_foreach(acc->nicks, mysql_storage_save_nick, &dbo);
	}
	
	/// Testing if my new g_string free funciton works
	free_g_str_list(5, acc_handle, acc_password, acc_protocol, acc_tag, account_id_str);
    }
    
    
    
    /// 4. Set all the channels
    {
	GSList* l;
	GSList* channel_row = NULL;
	GString* channel_id_str = NULL;
	GString *ch_name = g_string_new("");
	GString *ch_type = g_string_new("");
	
	/// 4.0 But first delete all the existing channels
	g_string_printf(q, "DELETE FROM channels WHERE `user` = '%lu'", user_id);
	send_query(mysql, q->str, q->len);
	
	for(l = irc->channels; l; l = l->next )
	{
	    irc_channel_t *ic = l->data;
	    g_string_printf(ch_name, "%s", ic->name);
	    //g_string_printf(ch_type, "set_getstr(&ic->set, \"type\")");
	    g_string_printf(ch_type, "%s", set_getstr(&ic->set, "type"));
	    
	    if( ic->flags & IRC_CHANNEL_TEMP )
		continue;

	    /// 4.1 save channel
	    save_kv_pair(q, buf, "channels", "user", "name", "type", user_id, ch_name->str, ch_type->str);

	    /// fetch channel id
	    g_string_printf(q, "select id from channels where user='%ld' and name='", user_id);
	    append_mysql_escaped_param(q, buf, ch_name);
	    g_string_append(q, "' and type='");
	    append_mysql_escaped_param(q, buf, ch_type);
	    g_string_append(q, "'");
	    channel_row =  mysql_single_row(mysql, q->str);
	    channel_id_str = (GString*)(channel_row->data);
	    
	    /// 4.2 save channel settings
	    /// the last condition here is a bit geeky.
	    /// its like this becase of refactoring the code. 
	    set_channel_settings(mysql, ic->set, "channel_settings", "channel", atol(channel_id_str->str));
	    
	}
	free_g_str_list(2, ch_name, ch_type);
	mysql_free_single_row(channel_row);
    }
    
    g_string_free(nick, TRUE);
    g_string_free(pass, TRUE);
    g_string_free(buf, TRUE);
    g_string_free(q, TRUE);
    /// all went good till now.
    return STORAGE_OK;
}    

static storage_status_t mysql_storage_remove( const char *nick, const char *password ) {
    int query_status =0;
    
    /// GString wrapper for string params 
    GString *g_nick = g_string_new(nick);
    GString *g_password = g_string_new(password);
    
    /// Query and buffer
    GString *buffer=g_string_new(""), *query = g_string_new("DELETE FROM users where nick='");
    append_mysql_escaped_param(query, buffer, g_nick);
    g_string_append(query,"' and password=sha1('");
    append_mysql_escaped_param(query, buffer, g_password);
    g_string_append(query, "')");
    
    query_status = send_query(mysql, query->str, query->len);
    
    /// Free glib objects
    g_string_free(g_nick, TRUE);
    g_string_free(g_password, TRUE);
    g_string_free(query, TRUE);
    g_string_free(buffer, TRUE);
    
    if(query_status==0){
	 if(mysql_affected_rows(mysql) == 1){
	     return STORAGE_OK;
	 }else{
	     /// @TODO should we check if password is wrong and return STORAGE_INVALID_PASSWORD?
	     return STORAGE_NO_SUCH_USER;
	 }
    }else{
	fprintf(stderr, "\e[31mERROR\t%s\e[0m\n", mysql_error(mysql));
	return STORAGE_OTHER_ERROR;
    }
}

static void mysql_storage_deinit( void ) {
    if(mysql!=NULL) {
        mysql_close(mysql);
    }
}

/**
 * If a table has key-value options associated with it in on-to-many 
 * relation this function helps to save those options.
 * @param q query buffer
 * @param buf buffer to use for building query.
 * @param table_name name of the child table
 * @param fk_column_name foreign key column name mapped to parent
 * @param key_name name of the key column in key-value
 * @param value_name name of the value column in key-value
 * @param fk_column_value value to set for fk_column_name
 * @param key value to set for key_name
 * @param value value to set for value_name
 */
static storage_status_t save_kv_pair(GString *q, GString *buf, char *table_name, 
		  char *fk_column_name, char *key_name, char *value_name, 
		  long fk_column_value, char *key, char *value){
    GString *v = g_string_new("");
    GString *k = g_string_new("");
    
    // building query.
    g_string_printf(k, "%s", key);
    g_string_printf(v, "%s", value);
    g_string_printf(q,"insert into  `%s` (`%s`, `%s`, `%s`) values (%ld, '", table_name, 
		    fk_column_name, key_name, value_name, fk_column_value);
    append_mysql_escaped_param(q, buf, k);
    g_string_append(q,"', '");
    append_mysql_escaped_param(q, buf, v);
    g_string_append_printf(q, "') on duplicate key update `%s`='", value_name);
    append_mysql_escaped_param(q, buf, v);
    g_string_append(q,"'");
    
    // executing query
    send_query(mysql,q->str,q->len);
    
    // releasing memory
    g_string_free(v, TRUE);
    g_string_free(k, TRUE);
    
    if(mysql_errno(mysql)!=0) {
	/// something bad happened!
	return STORAGE_OTHER_ERROR;
    }else{
	return STORAGE_OK;
    }
}

static void mysql_storage_save_nick(gpointer key, gpointer value, gpointer data){
    GString *query = ((database_object *)data)->query_string;
    GString *buffer = ((database_object *)data)->string_buffer;
    char * account_id = (char *)(((database_object *)data)->data);
    
    /*storage_status_t buddy_kv_stat = */save_kv_pair(query, buffer, "account_buddies", "account", "handle", "nick",
	atol(account_id), (char *)key, (char *)value);
}


storage_t storage_mysql = {
    .name = "mysql",
    .init = mysql_storage_init,
    .check_pass = mysql_storage_check_pass,
    .remove = mysql_storage_remove,
    .load = mysql_storage_load,
    .save = mysql_storage_save,
    .deinit = mysql_storage_deinit
};
