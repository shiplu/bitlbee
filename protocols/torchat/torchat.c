#include "nogaim.h"
#include "torchat.h"

GSList *torchat_connections;

void init_plugin()
{
	struct prpl *ret = g_new0(struct prpl, 1);

	ret->name = "torchat";
	ret->login = torchat_login;

	register_protocol(ret);
}
