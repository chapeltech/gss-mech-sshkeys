#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <gssapi.h>

static unsigned char sshkey_oid_elements[] = {
	0x2b, 0x06, 0x01, 0x04, 0x01, 0x86, 0x8d, 0x1f, 0x01
};

static gss_OID_desc sshkey_oid = {
	sizeof(sshkey_oid_elements), sshkey_oid_elements
};

int
main(int argc, char **argv)
{
	gss_buffer_desc	 in = GSS_C_EMPTY_BUFFER;
	gss_buffer_desc	 accept_final_out = GSS_C_EMPTY_BUFFER;
	gss_buffer_desc	 accept_out = GSS_C_EMPTY_BUFFER;
	gss_buffer_desc	 final_out = GSS_C_EMPTY_BUFFER;
	gss_buffer_desc	 name_buf;
	gss_buffer_desc	 out = GSS_C_EMPTY_BUFFER;
	gss_buffer_desc	 reply_unwrapped = GSS_C_EMPTY_BUFFER;
	gss_buffer_desc	 reply_wrapped = GSS_C_EMPTY_BUFFER;
	gss_buffer_desc	 sf_accept_final = GSS_C_EMPTY_BUFFER;
	gss_buffer_desc	 sf_challenge = GSS_C_EMPTY_BUFFER;
	gss_buffer_desc	 sf_response = GSS_C_EMPTY_BUFFER;
	gss_buffer_desc	 unwrapped = GSS_C_EMPTY_BUFFER;
	gss_buffer_desc	 wrapped = GSS_C_EMPTY_BUFFER;
	gss_ctx_id_t	 accept_ctx = GSS_C_NO_CONTEXT;
	gss_ctx_id_t	 ctx = GSS_C_NO_CONTEXT;
	gss_ctx_id_t	 sf_accept_ctx = GSS_C_NO_CONTEXT;
	gss_ctx_id_t	 sf_init_ctx = GSS_C_NO_CONTEXT;
	gss_iov_buffer_desc	 iov[4];
	gss_name_t	 service_name = GSS_C_NO_NAME;
	OM_uint32	 maj;
	OM_uint32	 min;
	gss_qop_t	 qop_state;
	int		 conf_state;
	char		 iov_plain[64];
	const char	*service;
	const char	*iov_meta = "sshkey metadata";
	const char	*iov_text = "sshkey iov plaintext";
	const char	*plain = "sshkey wrap plaintext";
	const char	*reply_plain = "sshkey reply plaintext";
	size_t		 iov_plain_len;
	int		 ret = 1;

	service = argc > 1 ? argv[1] : "sshkey@localhost";
	memset(iov, 0, sizeof(iov));
	name_buf.length = strlen(service);
	name_buf.value = (void *)service;

	maj = gss_import_name(&min, &name_buf, GSS_C_NT_HOSTBASED_SERVICE,
	    &service_name);
	if (GSS_ERROR(maj)) {
		fprintf(stderr, "gss_import_name failed: %u/%u\n", maj, min);
		goto out;
	}

	maj = gss_init_sec_context(&min, GSS_C_NO_CREDENTIAL, &ctx,
	    service_name, &sshkey_oid, 0, 0, GSS_C_NO_CHANNEL_BINDINGS, &in,
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

	maj = gss_accept_sec_context(&min, &accept_ctx, GSS_C_NO_CREDENTIAL,
	    &out, GSS_C_NO_CHANNEL_BINDINGS, NULL, NULL, &accept_out, NULL,
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
	    service_name, &sshkey_oid, 0, 0, GSS_C_NO_CHANNEL_BINDINGS,
	    &accept_out, NULL, &final_out, NULL, NULL);
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
	    &final_out, GSS_C_NO_CHANNEL_BINDINGS, NULL, NULL,
	    &accept_final_out, NULL, NULL, NULL);
	if (GSS_ERROR(maj)) {
		fprintf(stderr, "final gss_accept_sec_context failed: %u/%u\n",
		    maj, min);
		goto out;
	}
	if (maj & GSS_S_CONTINUE_NEEDED) {
		fprintf(stderr, "final gss_accept_sec_context needs continuation\n");
		goto out;
	}

	printf("final gss_accept_sec_context: complete token=%zu\n",
	    accept_final_out.length);

	if (getenv("SSHKEY_TEST_SERVER_FIRST") != NULL) {
		maj = gss_accept_sec_context(&min, &sf_accept_ctx,
		    GSS_C_NO_CREDENTIAL, GSS_C_NO_BUFFER,
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
		    GSS_C_NO_CREDENTIAL, &sf_response,
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
	gss_release_iov_buffer(&min, iov, 4);
	if (reply_unwrapped.length)
		gss_release_buffer(&min, &reply_unwrapped);
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

	return ret;
}
