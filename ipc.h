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

void ipc_master_read( gpointer data, gint source, GaimInputCondition cond );
void ipc_child_read( gpointer data, gint source, GaimInputCondition cond );

void ipc_to_master( char **cmd );
void ipc_to_master_str( char *msg_buf );
void ipc_to_children( char **cmd );
void ipc_to_children_str( char *msg_buf );

struct bitlbee_child
{
	pid_t pid;
	int ipc_fd;
	gint ipc_inpa;
};

extern GSList *child_list;
