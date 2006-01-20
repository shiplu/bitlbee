  /********************************************************************\
  * BitlBee -- An IRC to other IM-networks gateway                     *
  *                                                                    *
  * Copyright 2002-2004 Wilmer van der Gaast and others                *
  \********************************************************************/

/* IPC - communication between BitlBee processes                        */

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


struct bitlbee_child
{
	pid_t pid;
	int ipc_fd;
	gint ipc_inpa;
	
	char *host;
	char *nick;
	char *realname;
};


void ipc_master_read( gpointer data, gint source, GaimInputCondition cond );
void ipc_child_read( gpointer data, gint source, GaimInputCondition cond );

void ipc_master_free_one( struct bitlbee_child *child );
void ipc_master_free_all();

void ipc_to_master( char **cmd );
void ipc_to_master_str( char *format, ... );
void ipc_to_children( char **cmd );
void ipc_to_children_str( char *format, ... );

/* We need this function in inetd mode, so let's just make it non-static. */
void ipc_master_cmd_rehash( irc_t *data, char **cmd );


extern GSList *child_list;
