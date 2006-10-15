/***************************************************************************\
*                                                                           *
*  BitlBee - An IRC to IM gateway                                           *
*  Jabber module - Handling of message(s) (tags), etc                       *
*                                                                           *
*  Copyright 2006 Wilmer van der Gaast <wilmer@gaast.net>                   *
*                                                                           *
*  This program is free software; you can redistribute it and/or modify     *
*  it under the terms of the GNU General Public License as published by     *
*  the Free Software Foundation; either version 2 of the License, or        *
*  (at your option) any later version.                                      *
*                                                                           *
*  This program is distributed in the hope that it will be useful,          *
*  but WITHOUT ANY WARRANTY; without even the implied warranty of           *
*  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the            *
*  GNU General Public License for more details.                             *
*                                                                           *
*  You should have received a copy of the GNU General Public License along  *
*  with this program; if not, write to the Free Software Foundation, Inc.,  *
*  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.              *
*                                                                           *
\***************************************************************************/

#include "jabber.h"

xt_status jabber_pkt_message( struct xt_node *node, gpointer data )
{
	struct gaim_connection *gc = data;
	char *from = xt_find_attr( node, "from" );
	char *type = xt_find_attr( node, "type" );
	struct xt_node *body = xt_find_node( node->children, "body" );
	char *s;
	
	if( !type )
		return XT_HANDLED;	/* Grmbl... FIXME */
	
	if( strcmp( type, "chat" ) == 0 )
	{
		struct jabber_buddy *bud = NULL;
		
		if( ( s = strchr( from, '/' ) ) == NULL )
		{
			/* It just shouldn't happen. */
			hide_login_progress( gc, "Received message packet from bare JID" );
			signoff( gc );
			return XT_ABORT;
		}
		
		if( ( bud = jabber_buddy_by_jid( gc, from ) ) )
			bud->last_act = time( NULL );
		else
			*s = 0; /* We need to generate a bare JID now. */
		
		if( body ) /* Could be just a typing notification. */
			serv_got_im( gc, bud ? bud->handle : from, body->text, 0, 0, 0 );
		
		/* Handling of incoming typing notifications. */
		if( xt_find_node( node->children, "composing" ) )
		{
			bud->flags |= JBFLAG_DOES_XEP85;
			serv_got_typing( gc, bud ? bud->handle : from, 0, 1 );
		}
		/* No need to send a "stopped typing" signal when there's a message. */
		else if( xt_find_node( node->children, "active" ) && ( body == NULL ) )
		{
			bud->flags |= JBFLAG_DOES_XEP85;
			serv_got_typing( gc, bud ? bud->handle : from, 0, 0 );
		}
		else if( xt_find_node( node->children, "paused" ) )
		{
			bud->flags |= JBFLAG_DOES_XEP85;
			serv_got_typing( gc, bud ? bud->handle : from, 0, 2 );
		}
		
		if( s )
			*s = '/'; /* And convert it back to a full JID. */
	}
	else
	{
		printf( "Received MSG from %s:\n", from );
		xt_print( node );
	}
	
	return XT_HANDLED;
}
