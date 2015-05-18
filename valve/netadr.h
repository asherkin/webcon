//========= Copyright (c) 1996-2005, Valve Corporation, All rights reserved. ============//
//
// Purpose: 
//
// $NoKeywords: $
//
//=============================================================================//
// netadr.h
#ifndef NETADR_H
#define NETADR_H

#ifdef _WIN32
#pragma once
#endif

typedef enum
{ 
	NA_NULL = 0,
	NA_LOOPBACK,
	NA_BROADCAST,
	NA_IP,
} netadrtype_t;

typedef struct netadr_s
{
public:
	netadr_s() { Clear(); }
	void	Clear();	// invalids Address
	bool	SetFromSockadr(const struct sockaddr *s);

public:	// members are public to avoid to much changes
	netadrtype_t	type;
	unsigned char	ip[4];
	unsigned short	port;
} netadr_t;

void netadr_t::Clear()
{
	ip[0] = ip[1] = ip[2] = ip[3] = 0;
	port = 0;
	type = NA_NULL;
}

bool netadr_t::SetFromSockadr(const struct sockaddr * s)
{
	if (s->sa_family == AF_INET)
	{
		type = NA_IP;
		*(int *)&ip = ((struct sockaddr_in *)s)->sin_addr.s_addr;
		port = ((struct sockaddr_in *)s)->sin_port;
		return true;
	}
	else
	{
		Clear();
		return false;
	}
}

#endif // NETADR_H
