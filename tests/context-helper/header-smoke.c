#include "gss_sshkey.h"

int
main(void)
{
	const unsigned char host_key[] = { 0, 1, 2, 3 };
	gss_sshkey_context_field client[] = {
		gss_sshkey_context_string(GSS_SSHKEY_FIELD_USER, "alice"),
		gss_sshkey_context_bytes(GSS_SSHKEY_FIELD_HOST_KEY, host_key,
		    sizeof(host_key)),
	};
	gss_sshkey_context_field server[] = {
		gss_sshkey_context_string(GSS_SSHKEY_FIELD_PEER_ADDRESS,
		    "192.0.2.10"),
	};
	OM_uint32 minor = 0;
	OM_uint32 major = 0;

	if (GSS_SSHKEY_CONTEXT_VERSION_1 != 1 ||
	    GSS_SSHKEY_CONTEXT_CLIENT == GSS_SSHKEY_CONTEXT_SERVER ||
	    GSS_SSHKEY_CONTEXT_ALL == GSS_SSHKEY_CONTEXT_CLIENT)
		return 1;

	major |= gss_sshkey_set_client_context(&minor, client,
	    GSS_SSHKEY_ARRAY_LEN(client));
	major |= gss_sshkey_set_server_context(&minor, server,
	    GSS_SSHKEY_ARRAY_LEN(server));
	major |= gss_sshkey_clear_context_fields(&minor,
	    GSS_SSHKEY_CONTEXT_ALL);

	return major == 0 ? 0 : 1;
}
