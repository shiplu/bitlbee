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
#include "base64.h"
#include "arc.h"
#include "sha1.h"
#include <mysql/mysql.h>

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
static void mysql_storage_init( void );
static storage_status_t mysql_storage_load( irc_t *irc, const char *password );
static storage_status_t mysql_storage_check_pass( const char *my_nick, const char *password );
static storage_status_t mysql_storage_save( irc_t *irc, int overwrite );
static storage_status_t mysql_storage_remove( const char *nick, const char *password );
static void mysql_storage_deinit( void );
struct mysql_parsedata
{
    irc_t *irc;
    char *current_setting;
    account_t *current_account;
    irc_channel_t *current_channel;
    set_t **current_set_head;
    char *given_nick;
    char *given_pass;
    mysql_pass_st pass_st;
    int unknown_tag;
};

MYSQL *mysql = NULL;

static void mysql_storage_init( void ) {
    if (mysql_init(mysql) == NULL) {
        log_message( LOGLVL_WARNING, "Can not initialize MySQL. Configuration won't be saved.");
    }
    if (!mysql_real_connect
            (mysql, "localhost", "USERNAME", "PASSWORD", NULL, 0, NULL, 0)) {
	log_message( LOGLVL_WARNING, "%s\nConfiguration won't be saved.", mysql_error(mysql));
    }

    if (mysql_select_db(mysql, "DATABASENAME")) {
        log_message( LOGLVL_WARNING, "%s\nConfiguration won't be saved.", mysql_error(mysql));
    }
}
static storage_status_t mysql_storage_load( irc_t *irc, const char *password ) {
    return STORAGE_OTHER_ERROR;
}
static storage_status_t mysql_storage_check_pass( const char *my_nick, const char *password ) {
    return STORAGE_OTHER_ERROR;
}
static storage_status_t mysql_storage_save( irc_t *irc, int overwrite ) {
    return STORAGE_OTHER_ERROR;
}
static storage_status_t mysql_storage_remove( const char *nick, const char *password ) {
    return STORAGE_OTHER_ERROR;
}

static void mysql_storage_deinit( void ) {
    if(mysql!=NULL) {
        mysql_close(mysql);
    }
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
