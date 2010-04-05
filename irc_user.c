  /********************************************************************\
  * BitlBee -- An IRC to other IM-networks gateway                     *
  *                                                                    *
  * Copyright 2002-2004 Wilmer van der Gaast and others                *
  \********************************************************************/

/* Stuff to handle, save and search IRC buddies                         */

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

#include "bitlbee.h"

irc_user_t *irc_user_new( irc_t *irc, const char *nick )
{
	irc_user_t *iu = g_new0( irc_user_t, 1 );
	
	iu->irc = irc;
	iu->nick = g_strdup( nick );
	iu->user = iu->host = iu->fullname = iu->nick;
	
	iu->flags = set_getbool( &irc->b->set, "private" ) ? IRC_USER_PRIVATE : 0;
	
	iu->key = g_strdup( nick );
	nick_lc( iu->key );
	/* Using the hash table for speed and irc->users for easy iteration
	   through the list (since the GLib API doesn't have anything sane
	   for that.) */
	g_hash_table_insert( irc->nick_user_hash, iu->key, iu );
	irc->users = g_slist_insert_sorted( irc->users, iu, irc_user_cmp );
	
	return iu;
}

int irc_user_free( irc_t *irc, const char *nick )
{
	irc_user_t *iu;
	GSList *l;
	
	if( !( iu = irc_user_by_name( irc, nick ) ) )
		return 0;
	
	irc->users = g_slist_remove( irc->users, iu );
	g_hash_table_remove( irc->nick_user_hash, iu->key );
	
	for( l = irc->channels; l; l = l->next )
		irc_channel_del_user( (irc_channel_t*) l->data, iu );
	
	g_free( iu->nick );
	if( iu->nick != iu->user ) g_free( iu->user );
	if( iu->nick != iu->host ) g_free( iu->host );
	if( iu->nick != iu->fullname ) g_free( iu->fullname );
	g_free( iu->sendbuf );
	if( iu->sendbuf_timer ) b_event_remove( iu->sendbuf_timer );
	g_free( iu->key );
	
	return 1;
}

irc_user_t *irc_user_by_name( irc_t *irc, const char *nick )
{
	char key[strlen(nick)+1];
	
	strcpy( key, nick );
	if( nick_lc( key ) )
		return g_hash_table_lookup( irc->nick_user_hash, key );
	else
		return NULL;
}

int irc_user_set_nick( irc_user_t *iu, const char *new )
{
	irc_t *irc = iu->irc;
	char key[strlen(new)+1];
	GSList *cl;
	
	strcpy( key, new );
	if( iu == NULL || !nick_lc( key ) || irc_user_by_name( irc, new ) )
		return 0;
	
	for( cl = irc->channels; cl; cl = cl->next )
	{
		irc_channel_t *ic = cl->data;
		
		/* Send a NICK update if we're renaming our user, or someone
		   who's in the same channel like our user. */
		if( iu == irc->user ||
		    ( ( ic->flags & IRC_CHANNEL_JOINED ) &&
		      irc_channel_has_user( ic, iu ) ) )
		{
			irc_send_nick( iu, new );
			break;
		}
	}
	
	irc->users = g_slist_remove( irc->users, iu );
	g_hash_table_remove( irc->nick_user_hash, iu->key );
	
	if( iu->nick == iu->user ) iu->user = NULL;
	if( iu->nick == iu->host ) iu->host = NULL;
	if( iu->nick == iu->fullname ) iu->fullname = NULL;
	g_free( iu->nick );
	iu->nick = g_strdup( new );
	if( iu->user == NULL ) iu->user = g_strdup( iu->nick );
	if( iu->host == NULL ) iu->host = g_strdup( iu->nick );
	if( iu->fullname == NULL ) iu->fullname = g_strdup( iu->nick );
	
	iu->key = g_strdup( key );
	g_hash_table_insert( irc->nick_user_hash, iu->key, iu );
	irc->users = g_slist_insert_sorted( irc->users, iu, irc_user_cmp );
	
	return 1;
}

gint irc_user_cmp( gconstpointer a_, gconstpointer b_ )
{
	const irc_user_t *a = a_, *b = b_;
	
	return strcmp( a->key, b->key );
}

/* User-type dependent functions, for root/NickServ: */
static gboolean root_privmsg( irc_user_t *iu, const char *msg )
{
	char cmd[strlen(msg)+1];
	
	g_free( iu->irc->last_root_cmd );
	iu->irc->last_root_cmd = g_strdup( iu->nick );
	
	strcpy( cmd, msg );
	root_command_string( iu->irc, cmd );
	
	return TRUE;
}

const struct irc_user_funcs irc_user_root_funcs = {
	root_privmsg,
};

/* Echo to yourself: */
static gboolean self_privmsg( irc_user_t *iu, const char *msg )
{
	irc_send_msg_raw( iu, "PRIVMSG", iu->nick, msg );
	
	return TRUE;
}

const struct irc_user_funcs irc_user_self_funcs = {
	self_privmsg,
};
