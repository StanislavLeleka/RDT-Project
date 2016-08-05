#include "network_listener.h"

int main()
{
	network_listener *nl = new network_listener(false, "", "tcp");
	
	nl->start_listening(false, false, NULL);
	
	return 0;
}