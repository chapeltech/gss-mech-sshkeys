#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <gssapi.h>
#include "gss_sshkey.h"
#if defined(KRB5_CALLCONV) && defined(__has_include)
#if __has_include(<gssapi/gssapi_ext.h>)
#include <gssapi/gssapi_ext.h>
#endif
#endif

#ifndef GSS_C_CHANNEL_BOUND_FLAG
#define GSS_C_CHANNEL_BOUND_FLAG 2048
#endif

static unsigned char sshkey_oid_elements[] = {
	0x2b, 0x06, 0x01, 0x04, 0x01, 0x86, 0x8d, 0x1f, 0x01
};

static gss_OID_desc sshkey_oid = {
	sizeof(sshkey_oid_elements), sshkey_oid_elements
};

typedef OM_uint32 (*set_context_fields_fn)(OM_uint32 *, OM_uint32,
    OM_uint32, const gss_sshkey_context_field *, size_t);

static int
stage_peer_address(const char *peer)
{
	gss_sshkey_context_field field;
	set_context_fields_fn set_fields;
	OM_uint32 maj;
	OM_uint32 min;

	set_fields = (set_context_fields_fn)dlsym(RTLD_DEFAULT,
	    "gss_sshkey_set_context_fields");
	if (set_fields == NULL) {
		fprintf(stderr, "gss_sshkey_set_context_fields unavailable\n");
		return 0;
	}
	field = gss_sshkey_context_string(GSS_SSHKEY_FIELD_PEER_ADDRESS,
	    peer);
	maj = set_fields(&min, GSS_SSHKEY_CONTEXT_SERVER,
	    GSS_SSHKEY_CONTEXT_VERSION_1, &field, 1);
	if (GSS_ERROR(maj)) {
		fprintf(stderr, "staging peer address failed: %u/%u\n",
		    maj, min);
		return 0;
	}
	return 1;
}

int
main(int argc, char **argv)
{
	gss_buffer_desc	 in = GSS_C_EMPTY_BUFFER;
	gss_buffer_desc	 accept_final_out = GSS_C_EMPTY_BUFFER;
	gss_buffer_desc	 accept_out = GSS_C_EMPTY_BUFFER;
	gss_buffer_desc	 cb_out = GSS_C_EMPTY_BUFFER;
	gss_buffer_desc	 final_out = GSS_C_EMPTY_BUFFER;
	gss_buffer_desc	 mic = GSS_C_EMPTY_BUFFER;
	gss_buffer_desc	 peer_accept_out = GSS_C_EMPTY_BUFFER;
	gss_buffer_desc	 peer_final_out = GSS_C_EMPTY_BUFFER;
	gss_buffer_desc	 peer_init_out = GSS_C_EMPTY_BUFFER;
	gss_buffer_desc	 name_buf;
	gss_buffer_desc	 out = GSS_C_EMPTY_BUFFER;
	gss_buffer_desc	 reply_unwrapped = GSS_C_EMPTY_BUFFER;
	gss_buffer_desc	 reply_wrapped = GSS_C_EMPTY_BUFFER;
	gss_buffer_desc	 retry_out = GSS_C_EMPTY_BUFFER;
	gss_buffer_desc	 sf_accept_final = GSS_C_EMPTY_BUFFER;
	gss_buffer_desc	 sf_challenge = GSS_C_EMPTY_BUFFER;
	gss_buffer_desc	 sf_response = GSS_C_EMPTY_BUFFER;
	gss_buffer_desc	 source_buf = GSS_C_EMPTY_BUFFER;
	gss_buffer_desc	 unwrapped = GSS_C_EMPTY_BUFFER;
	gss_buffer_desc	 wrapped = GSS_C_EMPTY_BUFFER;
	gss_ctx_id_t	 accept_ctx = GSS_C_NO_CONTEXT;
	gss_ctx_id_t	 cb_ctx = GSS_C_NO_CONTEXT;
	gss_ctx_id_t	 ctx = GSS_C_NO_CONTEXT;
	gss_ctx_id_t	 peer_accept_ctx = GSS_C_NO_CONTEXT;
	gss_ctx_id_t	 peer_init_ctx = GSS_C_NO_CONTEXT;
	gss_ctx_id_t	 sf_accept_ctx = GSS_C_NO_CONTEXT;
	gss_ctx_id_t	 sf_init_ctx = GSS_C_NO_CONTEXT;
	gss_cred_id_t	 sf_acceptor_cred = GSS_C_NO_CREDENTIAL;
	gss_iov_buffer_desc	 iov[4];
	gss_name_t	 service_name = GSS_C_NO_NAME;
	gss_name_t	 source_name = GSS_C_NO_NAME;
	gss_OID_set	 mechanisms = GSS_C_NO_OID_SET;
	gss_OID_set	 sf_mechanisms = GSS_C_NO_OID_SET;
	OM_uint32	 maj;
	OM_uint32	 min;
	OM_uint32	 accept_flags = 0;
	OM_uint32	 init_flags = 0;
	gss_qop_t	 qop_state;
	int		 conf_state;
	int		 mechanism_present = 0;
	char		 iov_plain[64];
	const char	*service;
	const char	*expected_user;
	const char	*iov_meta = "sshkey metadata";
	const char	*iov_text = "sshkey iov plaintext";
	const char	*mic_plain = "sshkey MIC plaintext";
	const char	*plain = "sshkey wrap plaintext";
	const char	*peer_address;
	const char	*reply_plain = "sshkey reply plaintext";
	const char	*binding_data = "sshkey channel binding";
	const char	*mismatch_data = "different channel binding";
	unsigned char	 acceptor_address[] = { 192, 0, 2, 2 };
	unsigned char	 initiator_address[] = { 192, 0, 2, 1 };
	struct gss_channel_bindings_struct bindings;
	struct gss_channel_bindings_struct mismatch_bindings;
	size_t		 iov_plain_len;
	int		 ret = 1;

	service = argc > 1 ? argv[1] : "sshkey@localhost";
	expected_user = getenv("SSHKEY_TEST_EXPECTED_USER");
	memset(iov, 0, sizeof(iov));
	memset(&bindings, 0, sizeof(bindings));
	bindings.initiator_addrtype = GSS_C_AF_INET;
	bindings.initiator_address.length = sizeof(initiator_address);
	bindings.initiator_address.value = initiator_address;
	bindings.acceptor_addrtype = GSS_C_AF_INET;
	bindings.acceptor_address.length = sizeof(acceptor_address);
	bindings.acceptor_address.value = acceptor_address;
	bindings.application_data.length = strlen(binding_data);
	bindings.application_data.value = (void *)binding_data;
	mismatch_bindings = bindings;
	mismatch_bindings.application_data.length = strlen(mismatch_data);
	mismatch_bindings.application_data.value = (void *)mismatch_data;
	name_buf.length = strlen(service);
	name_buf.value = (void *)service;

	maj = gss_indicate_mechs(&min, &mechanisms);
	if (GSS_ERROR(maj)) {
		fprintf(stderr, "gss_indicate_mechs failed: %u/%u\n", maj, min);
		goto out;
	}
	maj = gss_test_oid_set_member(&min, &sshkey_oid, mechanisms,
	    &mechanism_present);
	if (GSS_ERROR(maj) || !mechanism_present) {
		fprintf(stderr, "sshkey mechanism is not registered: %u/%u\n",
		    maj, min);
		goto out;
	}

	maj = gss_import_name(&min, &name_buf, GSS_C_NT_HOSTBASED_SERVICE,
	    &service_name);
	if (GSS_ERROR(maj)) {
		fprintf(stderr, "gss_import_name failed: %u/%u\n", maj, min);
		goto out;
	}
	if (getenv("SSHKEY_TEST_SERVER_FIRST") != NULL) {
		maj = gss_create_empty_oid_set(&min, &sf_mechanisms);
		if (!GSS_ERROR(maj))
			maj = gss_add_oid_set_member(&min, &sshkey_oid,
			    &sf_mechanisms);
		if (!GSS_ERROR(maj))
			maj = gss_acquire_cred(&min, service_name,
			    GSS_C_INDEFINITE, sf_mechanisms, GSS_C_ACCEPT,
			    &sf_acceptor_cred, NULL, NULL);
		if (GSS_ERROR(maj)) {
			fprintf(stderr, "acceptor credential failed: %u/%u\n",
			    maj, min);
			goto out;
		}
	}

	maj = gss_init_sec_context(&min, GSS_C_NO_CREDENTIAL, &cb_ctx,
	    service_name, &sshkey_oid, 0, 0, &bindings, &in, NULL, &cb_out,
	    NULL, NULL);
	if (GSS_ERROR(maj) || (maj & GSS_S_CONTINUE_NEEDED) == 0) {
		fprintf(stderr, "channel-binding setup failed: %u/%u\n",
		    maj, min);
		goto out;
	}
	maj = gss_init_sec_context(&min, GSS_C_NO_CREDENTIAL, &cb_ctx,
	    service_name, &sshkey_oid, 0, 0, &mismatch_bindings, &in, NULL,
	    &final_out, NULL, NULL);
	if (maj != GSS_S_BAD_BINDINGS) {
		fprintf(stderr, "changed channel bindings returned: %u/%u\n",
		    maj, min);
		goto out;
	}
	gss_release_buffer(&min, &cb_out);
	gss_delete_sec_context(&min, &cb_ctx, GSS_C_NO_BUFFER);
	printf("channel-binding change: rejected\n");

	if (getenv("SSHKEY_TEST_PEER_BINDING_MISMATCH") != NULL) {
		maj = gss_init_sec_context(&min, GSS_C_NO_CREDENTIAL,
		    &peer_init_ctx, service_name, &sshkey_oid, 0, 0,
		    &bindings, &in, NULL, &peer_init_out, NULL, NULL);
		if (GSS_ERROR(maj) ||
		    (maj & GSS_S_CONTINUE_NEEDED) == 0) {
			fprintf(stderr, "peer binding init failed: %u/%u\n",
			    maj, min);
			goto out;
		}
		maj = gss_accept_sec_context(&min, &peer_accept_ctx,
		    GSS_C_NO_CREDENTIAL, &peer_init_out, &mismatch_bindings,
		    NULL, NULL, &peer_accept_out, NULL, NULL, NULL);
		if (GSS_ERROR(maj) ||
		    (maj & GSS_S_CONTINUE_NEEDED) == 0) {
			fprintf(stderr, "peer binding accept failed: %u/%u\n",
			    maj, min);
			goto out;
		}
		maj = gss_init_sec_context(&min, GSS_C_NO_CREDENTIAL,
		    &peer_init_ctx, service_name, &sshkey_oid, 0, 0,
		    &bindings, &peer_accept_out, NULL, &peer_final_out, NULL,
		    NULL);
		if (!GSS_ERROR(maj)) {
			fprintf(stderr, "peer channel-binding mismatch accepted\n");
			goto out;
		}
		printf("peer channel-binding mismatch: rejected\n");
	}

	maj = gss_init_sec_context(&min, GSS_C_NO_CREDENTIAL, &ctx,
	    service_name, &sshkey_oid, 0, 0, &bindings, &in,
	    NULL, &out, NULL, NULL);
	if (GSS_ERROR(maj)) {
		fprintf(stderr, "gss_init_sec_context failed: %u/%u\n",
		    maj, min);
		goto out;
	}
	if ((maj & GSS_S_CONTINUE_NEEDED) == 0) {
		fprintf(stderr, "gss_init_sec_context unexpectedly complete\n");
		goto out;
	}
	if (out.length == 0 || out.value == NULL) {
		fprintf(stderr, "gss_init_sec_context returned empty token\n");
		goto out;
	}

	printf("gss_init_sec_context: continue token=%zu\n", out.length);
	peer_address = getenv("SSHKEY_TEST_PEER_ADDRESS");
	if (peer_address != NULL && !stage_peer_address(peer_address))
		goto out;

	maj = gss_accept_sec_context(&min, &accept_ctx, GSS_C_NO_CREDENTIAL,
	    &out, &bindings, NULL, NULL, &accept_out, NULL,
	    NULL, NULL);
	if (GSS_ERROR(maj)) {
		fprintf(stderr, "gss_accept_sec_context failed: %u/%u\n",
		    maj, min);
		goto out;
	}
	if ((maj & GSS_S_CONTINUE_NEEDED) == 0) {
		fprintf(stderr, "gss_accept_sec_context unexpectedly complete\n");
		goto out;
	}
	if (accept_out.length == 0 || accept_out.value == NULL) {
		fprintf(stderr, "gss_accept_sec_context returned empty token\n");
		goto out;
	}

	printf("gss_accept_sec_context: continue token=%zu\n",
	    accept_out.length);

	maj = gss_init_sec_context(&min, GSS_C_NO_CREDENTIAL, &ctx,
	    service_name, &sshkey_oid, 0, 0, &bindings, &accept_out, NULL,
	    &final_out, &init_flags, NULL);
	if (getenv("SSHKEY_TEST_EXPECT_HOST_REJECT") != NULL) {
		if (!GSS_ERROR(maj)) {
			fprintf(stderr, "rejected host key was accepted\n");
			goto out;
		}
		printf("rejected host key: rejected\n");
		ret = 0;
		goto out;
	}
	if (getenv("SSHKEY_TEST_EXPECT_NO_USER_CRED") != NULL) {
		if (!GSS_ERROR(maj)) {
			fprintf(stderr, "missing user credential was accepted\n");
			goto out;
		}
		printf("missing user credential: rejected\n");
		ret = 0;
		goto out;
	}
	if (GSS_ERROR(maj)) {
		fprintf(stderr, "final gss_init_sec_context failed: %u/%u\n",
		    maj, min);
		goto out;
	}
	if (maj & GSS_S_CONTINUE_NEEDED) {
		fprintf(stderr, "final gss_init_sec_context needs continuation\n");
		goto out;
	}

	printf("final gss_init_sec_context: complete token=%zu\n",
	    final_out.length);
	if (final_out.length == 0 || final_out.value == NULL) {
		fprintf(stderr, "final gss_init_sec_context returned no token\n");
		goto out;
	}

	maj = gss_accept_sec_context(&min, &accept_ctx, GSS_C_NO_CREDENTIAL,
	    &final_out, &bindings, &source_name, NULL, &accept_final_out,
	    &accept_flags, NULL, NULL);
	if (getenv("SSHKEY_TEST_EXPECT_USER_REJECT") != NULL) {
		if (GSS_ERROR(maj)) {
			printf("rejected user key or policy: rejected\n");
			ret = 0;
			goto out;
		}
		if ((maj & GSS_S_CONTINUE_NEEDED) == 0 ||
		    accept_final_out.length == 0) {
			fprintf(stderr, "rejected user key completed context\n");
			goto out;
		}
		maj = gss_init_sec_context(&min, GSS_C_NO_CREDENTIAL, &ctx,
		    service_name, &sshkey_oid, 0, 0, &bindings,
		    &accept_final_out, NULL, &retry_out, NULL, NULL);
		if (!GSS_ERROR(maj)) {
			fprintf(stderr, "rejected user retry was accepted\n");
			goto out;
		}
		printf("rejected user key or policy: rejected\n");
		ret = 0;
		goto out;
	}
	if (GSS_ERROR(maj)) {
		fprintf(stderr, "final gss_accept_sec_context failed: %u/%u\n",
		    maj, min);
		goto out;
	}
	if (maj & GSS_S_CONTINUE_NEEDED) {
		fprintf(stderr, "final gss_accept_sec_context needs continuation\n");
		goto out;
	}
	if ((init_flags & GSS_C_CHANNEL_BOUND_FLAG) == 0 ||
	    (accept_flags & GSS_C_CHANNEL_BOUND_FLAG) == 0) {
		fprintf(stderr, "established context is not channel bound\n");
		goto out;
	}
	if (expected_user == NULL) {
		fprintf(stderr, "SSHKEY_TEST_EXPECTED_USER is not set\n");
		goto out;
	}
	maj = gss_display_name(&min, source_name, &source_buf, NULL);
	if (GSS_ERROR(maj) || source_buf.length != strlen(expected_user) ||
	    memcmp(source_buf.value, expected_user, source_buf.length) != 0) {
		fprintf(stderr, "authenticated source name is not requested user\n");
		goto out;
	}
	if (!gss_userok(source_name, expected_user) ||
	    gss_userok(source_name, "gss-sshkey-not-requested")) {
		fprintf(stderr, "gss_userok local-name authorization failed\n");
		goto out;
	}

	printf("final gss_accept_sec_context: complete token=%zu user=%s\n",
	    accept_final_out.length, expected_user);
	printf("gss_userok: requested local name accepted\n");

	if (getenv("SSHKEY_TEST_SERVER_FIRST") != NULL) {
		maj = gss_accept_sec_context(&min, &sf_accept_ctx,
		    sf_acceptor_cred, GSS_C_NO_BUFFER,
		    GSS_C_NO_CHANNEL_BINDINGS, NULL, NULL, &sf_challenge,
		    NULL, NULL, NULL);
		if (GSS_ERROR(maj)) {
			fprintf(stderr, "server-first accept failed: %u/%u\n",
			    maj, min);
			goto out;
		}
		if ((maj & GSS_S_CONTINUE_NEEDED) == 0) {
			fprintf(stderr, "server-first accept complete\n");
			goto out;
		}
		if (sf_challenge.length == 0 || sf_challenge.value == NULL) {
			fprintf(stderr, "server-first accept empty token\n");
			goto out;
		}

		maj = gss_init_sec_context(&min, GSS_C_NO_CREDENTIAL,
		    &sf_init_ctx, service_name, &sshkey_oid, 0, 0,
		    GSS_C_NO_CHANNEL_BINDINGS, &sf_challenge, NULL,
		    &sf_response, NULL, NULL);
		if (GSS_ERROR(maj)) {
			fprintf(stderr, "server-first init failed: %u/%u\n",
			    maj, min);
			goto out;
		}
		if (maj & GSS_S_CONTINUE_NEEDED) {
			fprintf(stderr, "server-first init needs continuation\n");
			goto out;
		}
		if (sf_response.length == 0 || sf_response.value == NULL) {
			fprintf(stderr, "server-first init empty token\n");
			goto out;
		}

		maj = gss_accept_sec_context(&min, &sf_accept_ctx,
		    sf_acceptor_cred, &sf_response,
		    GSS_C_NO_CHANNEL_BINDINGS, NULL, NULL, &sf_accept_final,
		    NULL, NULL, NULL);
		if (GSS_ERROR(maj)) {
			fprintf(stderr, "server-first final accept failed: "
			    "%u/%u\n", maj, min);
			goto out;
		}
		if (maj & GSS_S_CONTINUE_NEEDED) {
			fprintf(stderr, "server-first final needs continuation\n");
			goto out;
		}

		printf("server-first exchange: challenge=%zu response=%zu\n",
		    sf_challenge.length, sf_response.length);
	}

	in.length = strlen(plain);
	in.value = (void *)plain;
	maj = gss_wrap(&min, ctx, 1, 0, &in, &conf_state, &wrapped);
	if (GSS_ERROR(maj)) {
		fprintf(stderr, "initiator gss_wrap failed: %u/%u\n",
		    maj, min);
		goto out;
	}
	if (!conf_state || wrapped.length == 0 || wrapped.value == NULL) {
		fprintf(stderr, "initiator gss_wrap did not seal data\n");
		goto out;
	}

	maj = gss_unwrap(&min, accept_ctx, &wrapped, &unwrapped, &conf_state,
	    &qop_state);
	if (GSS_ERROR(maj)) {
		fprintf(stderr, "acceptor gss_unwrap failed: %u/%u\n",
		    maj, min);
		goto out;
	}
	if (!conf_state || unwrapped.length != strlen(plain) ||
	    memcmp(unwrapped.value, plain, unwrapped.length) != 0) {
		fprintf(stderr, "acceptor gss_unwrap plaintext mismatch\n");
		goto out;
	}

	printf("initiator gss_wrap: sealed token=%zu\n", wrapped.length);

	in.length = strlen(reply_plain);
	in.value = (void *)reply_plain;
	maj = gss_wrap(&min, accept_ctx, 0, 0, &in, &conf_state,
	    &reply_wrapped);
	if (GSS_ERROR(maj)) {
		fprintf(stderr, "acceptor gss_wrap failed: %u/%u\n",
		    maj, min);
		goto out;
	}
	if (conf_state || reply_wrapped.length == 0 ||
	    reply_wrapped.value == NULL) {
		fprintf(stderr, "acceptor gss_wrap unexpectedly sealed data\n");
		goto out;
	}

	maj = gss_unwrap(&min, ctx, &reply_wrapped, &reply_unwrapped,
	    &conf_state, &qop_state);
	if (GSS_ERROR(maj)) {
		fprintf(stderr, "initiator gss_unwrap failed: %u/%u\n",
		    maj, min);
		goto out;
	}
	if (conf_state || reply_unwrapped.length != strlen(reply_plain) ||
	    memcmp(reply_unwrapped.value, reply_plain,
	    reply_unwrapped.length) != 0) {
		fprintf(stderr, "initiator gss_unwrap plaintext mismatch\n");
		goto out;
	}

	printf("acceptor gss_wrap: signed token=%zu\n", reply_wrapped.length);

	in.length = strlen(mic_plain);
	in.value = (void *)mic_plain;
	maj = gss_get_mic(&min, ctx, 0, &in, &mic);
	if (GSS_ERROR(maj) || mic.length == 0 || mic.value == NULL) {
		fprintf(stderr, "initiator gss_get_mic failed: %u/%u\n",
		    maj, min);
		goto out;
	}
	maj = gss_verify_mic(&min, accept_ctx, &in, &mic, &qop_state);
	if (GSS_ERROR(maj)) {
		fprintf(stderr, "acceptor gss_verify_mic failed: %u/%u\n",
		    maj, min);
		goto out;
	}
	printf("initiator gss_get_mic: token=%zu\n", mic.length);

	iov_plain_len = strlen(iov_text);
	if (iov_plain_len > sizeof(iov_plain)) {
		fprintf(stderr, "IOV plaintext fixture too large\n");
		goto out;
	}
	memcpy(iov_plain, iov_text, iov_plain_len);
	iov[0].type = GSS_IOV_BUFFER_TYPE_HEADER |
	    GSS_IOV_BUFFER_FLAG_ALLOCATE;
	iov[1].type = GSS_IOV_BUFFER_TYPE_SIGN_ONLY;
	iov[1].buffer.length = strlen(iov_meta);
	iov[1].buffer.value = (void *)iov_meta;
	iov[2].type = GSS_IOV_BUFFER_TYPE_DATA;
	iov[2].buffer.length = iov_plain_len;
	iov[2].buffer.value = iov_plain;
	iov[3].type = GSS_IOV_BUFFER_TYPE_TRAILER |
	    GSS_IOV_BUFFER_FLAG_ALLOCATE;

	maj = gss_wrap_iov_length(&min, ctx, 1, 0, &conf_state, iov, 4);
	if (GSS_ERROR(maj)) {
		fprintf(stderr, "initiator gss_wrap_iov_length failed: %u/%u\n",
		    maj, min);
		goto out;
	}
	if (!conf_state || iov[0].buffer.length == 0 ||
	    iov[3].buffer.length == 0) {
		fprintf(stderr, "initiator gss_wrap_iov_length invalid sizes\n");
		goto out;
	}

	maj = gss_wrap_iov(&min, ctx, 1, 0, &conf_state, iov, 4);
	if (GSS_ERROR(maj)) {
		fprintf(stderr, "initiator gss_wrap_iov failed: %u/%u\n",
		    maj, min);
		goto out;
	}
	if (!conf_state || iov[0].buffer.length == 0 ||
	    iov[3].buffer.length == 0) {
		fprintf(stderr, "initiator gss_wrap_iov did not seal data\n");
		goto out;
	}

	maj = gss_unwrap_iov(&min, accept_ctx, &conf_state, &qop_state,
	    iov, 4);
	if (GSS_ERROR(maj)) {
		fprintf(stderr, "acceptor gss_unwrap_iov failed: %u/%u\n",
		    maj, min);
		goto out;
	}
	if (!conf_state || iov[2].buffer.length != iov_plain_len ||
	    memcmp(iov[2].buffer.value, iov_text, iov_plain_len) != 0) {
		fprintf(stderr, "acceptor gss_unwrap_iov plaintext mismatch\n");
		goto out;
	}

	printf("initiator gss_wrap_iov: sealed data=%zu\n",
	    iov[2].buffer.length);
	ret = 0;

out:
	if (sf_acceptor_cred != GSS_C_NO_CREDENTIAL)
		gss_release_cred(&min, &sf_acceptor_cred);
	if (sf_mechanisms != GSS_C_NO_OID_SET)
		gss_release_oid_set(&min, &sf_mechanisms);
	if (mechanisms != GSS_C_NO_OID_SET)
		gss_release_oid_set(&min, &mechanisms);
	gss_release_iov_buffer(&min, iov, 4);
	if (reply_unwrapped.length)
		gss_release_buffer(&min, &reply_unwrapped);
	if (retry_out.length)
		gss_release_buffer(&min, &retry_out);
	if (peer_final_out.length)
		gss_release_buffer(&min, &peer_final_out);
	if (peer_accept_out.length)
		gss_release_buffer(&min, &peer_accept_out);
	if (peer_init_out.length)
		gss_release_buffer(&min, &peer_init_out);
	if (mic.length)
		gss_release_buffer(&min, &mic);
	if (source_buf.length)
		gss_release_buffer(&min, &source_buf);
	if (reply_wrapped.length)
		gss_release_buffer(&min, &reply_wrapped);
	if (unwrapped.length)
		gss_release_buffer(&min, &unwrapped);
	if (wrapped.length)
		gss_release_buffer(&min, &wrapped);
	if (final_out.length)
		gss_release_buffer(&min, &final_out);
	if (accept_final_out.length)
		gss_release_buffer(&min, &accept_final_out);
	if (sf_accept_final.length)
		gss_release_buffer(&min, &sf_accept_final);
	if (sf_response.length)
		gss_release_buffer(&min, &sf_response);
	if (sf_challenge.length)
		gss_release_buffer(&min, &sf_challenge);
	if (accept_out.length)
		gss_release_buffer(&min, &accept_out);
	if (out.length)
		gss_release_buffer(&min, &out);
	if (cb_out.length)
		gss_release_buffer(&min, &cb_out);
	if (cb_ctx != GSS_C_NO_CONTEXT)
		gss_delete_sec_context(&min, &cb_ctx, GSS_C_NO_BUFFER);
	if (peer_accept_ctx != GSS_C_NO_CONTEXT)
		gss_delete_sec_context(&min, &peer_accept_ctx, GSS_C_NO_BUFFER);
	if (peer_init_ctx != GSS_C_NO_CONTEXT)
		gss_delete_sec_context(&min, &peer_init_ctx, GSS_C_NO_BUFFER);
	if (sf_accept_ctx != GSS_C_NO_CONTEXT)
		gss_delete_sec_context(&min, &sf_accept_ctx, GSS_C_NO_BUFFER);
	if (sf_init_ctx != GSS_C_NO_CONTEXT)
		gss_delete_sec_context(&min, &sf_init_ctx, GSS_C_NO_BUFFER);
	if (accept_ctx != GSS_C_NO_CONTEXT)
		gss_delete_sec_context(&min, &accept_ctx, GSS_C_NO_BUFFER);
	if (ctx != GSS_C_NO_CONTEXT)
		gss_delete_sec_context(&min, &ctx, GSS_C_NO_BUFFER);
	if (service_name != GSS_C_NO_NAME)
		gss_release_name(&min, &service_name);
	if (source_name != GSS_C_NO_NAME)
		gss_release_name(&min, &source_name);

	return ret;
}
