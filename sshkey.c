#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <gssapi.h>

#if 0
#include "gsssshkey_locl.h"
#include "gsskrb5_locl.h"
#include <gssapi_mech.h>
#endif


/* XXXrcd: shouldn't be here! */
struct gss_name_t_desc_struct {
	void *value;
	unsigned length;
};

/* XXXrcd: Internal structure definitions */

typedef struct {
	uint8_t sk[32];
	uint8_t pk[32];
	// XXXrcd: doesn't export properly:
	// /* krb5 context for message protection/PRF */
	// gss_ctx_id_t rfc4121;
	unsigned is_initiator : 1;
} *sshkey_ctx;

/*
 * XXXrcd: GBAIL() expects that ...
 */

#define GBAIL(x) do {					\
			gret = (x);			\
			if (gret != GSS_S_COMPLETE) 	\
				goto bail;		\
		} while (0)

/* Local functions */

static OM_uint32
unpack_or_create_ctx(OM_uint32 *min, sshkey_ctx *ctx, const gss_buffer_t buf)
{
	uint8_t		basepoint[32] = {9};

	/* XXXrcd: do we need to call gss_decapsulate_token()? */

	*min = 0;
	/* If we already have a context, we are finished */
	if (*ctx)
		return GSS_S_COMPLETE;

	/* Unpack buf if we have been passed one */
	/* XXXrcd: return if we unpack one */

	/* Otherwise, we create a context with a sk/pk pair */
	*ctx = calloc(1, sizeof(*ctx));
	if (!*ctx) {
		*min = ENOMEM;
		/* XXXrcd: new error... */
		return GSS_S_FAILURE;
	}
	/* XXXrcd: errors... */
	/* XXXrcd: no krb5 funcs... */
	krb5_generate_random_block((*ctx)->sk, 32);
	/* XXXrcd: these bitwise ops are unnecessary? */
	(*ctx)->sk[0]  &= 248;
	(*ctx)->sk[31] &= 127;
	(*ctx)->sk[31] |= 64;
	curve25519_donna((*ctx)->pk, (*ctx)->sk, basepoint);
	return GSS_S_COMPLETE;
}

/* Visible interface */

OM_uint32 GSSAPI_CALLCONV
gss_import_name(OM_uint32 *min, const gss_buffer_t in, const gss_OID type,
		gss_name_t *out)
{

	*out = calloc(1, sizeof(*out));
	if (!*out) {
		*min = ENOMEM;
		return GSS_S_FAILURE;
	}
	(*out)->value = strdup("foodlebrotz");
	(*out)->length = strlen((*out)->value);
	*min = 0;
	return GSS_S_COMPLETE;
}


OM_uint32 GSSAPI_CALLCONV
gss_init_sec_context(OM_uint32 *min,
		     gss_const_cred_id_t cred_handle,
		     gss_ctx_id_t *gctx,
		     gss_const_name_t target_name,
		     const gss_OID mech_type,
		     OM_uint32 req_flags,
		     OM_uint32 time_req,
		     const gss_channel_bindings_t input_chan_bindings,
		     const gss_buffer_t in,
		     gss_OID * actual_mech_type,
		     gss_buffer_t output_token,
		     OM_uint32 * ret_flags,
		     OM_uint32 * time_rec)
{
	OM_uint32	gret;

	*min = 0;
	output_token->length = 0;
	output_token->value = NULL;

	GBAIL(unpack_or_create_ctx(min, gctx, in));

	output_token->length = 6;
	output_token->value = strdup("hello\n");	/* XXXrcd: no no no */

bail:
	return GSS_S_COMPLETE;
}


OM_uint32 GSSAPI_CALLCONV
gss_accept_sec_context(OM_uint32 *min, gss_ctx_id_t *gctx,
		       gss_const_cred_id_t acceptor_cred_handle,
		       const gss_buffer_t in,
		       const gss_channel_bindings_t input_chan_bindings,
		       gss_name_t *src_name,
		       gss_OID *mech_type,
		       gss_buffer_t output_token,
		       OM_uint32 *ret_flags,
		       OM_uint32 *time_rec,
		       gss_cred_id_t *delegated_cred_handle)
{
	OM_uint32	gret;

	*min = 0;
	output_token->length = 0;
	output_token->value = NULL;

	/* XXXrcd: well... in future, we shouldn't be doing this one... */
	if (input_token_buffer->length != 6)
		return GSS_S_FAILURE;

	GBAIL(unpack_or_create_ctx(min, context_handle, in));

	if (strcmp(input_token_buffer->value, "hello\n") != 0)
		return GSS_S_FAILURE;

	*src_name = 1;
	gret = GSS_S_COMPLETE;
bail:
	return gret;
}

OM_uint32
gss_delete_sec_context(OM_uint32 *min, gss_ctx_id_t *gctx, gss_buffer_t out)
{
	sshkey_ctx ctx;

	*min = 0;
	if (out != GSS_C_NO_BUFFER) {
		out->length = 0;
		out->value  = NULL;
	}

	if (*gctx == GSS_C_NO_CONTEXT)
		return GSS_S_COMPLETE;

	ctx = (sshkey_ctx)gctx;
	*gctx = GSS_C_NO_CONTEXT;

	// XXXrcd: memset_s(ctx, 0x0, sizeof(*ctx));
	memset(ctx, 0x0, sizeof(*ctx));
	free(ctx);

	return GSS_S_COMPLETE;
}

OM_uint32 GSSAPI_CALLCONV
gss_display_name(OM_uint32 *min, gss_const_name_t in, gss_buffer_t out,
		 gss_OID *type)
{

	*min = 0;
	out->value = strdup("elric-kajsdnfjkasdnf");
	out->length = strlen(out->value);
	return GSS_S_COMPLETE;
}

GSSAPI_LIB_FUNCTION OM_uint32 GSSAPI_LIB_CALL
gss_export_name(OM_uint32 *min, gss_const_name_t in, gss_buffer_t out)
{

	*min = 0;
	out->value = strdup("elric-kajsdnfjkasdnf");
	out->length = strlen(out->value);
	return GSS_S_COMPLETE;
}

GSSAPI_LIB_FUNCTION OM_uint32 GSSAPI_LIB_CALL
gss_wrap(OM_uint32 *min, gss_const_ctx_id_t ctx, int conf_req_flag,
	 gss_qop_t qop_req, const gss_buffer_t in, int *conf,
	 gss_buffer_t out)
{

	*min = 0;
	out->length = in->length;
	out->value = malloc(in->length);
	memcpy(out->value, in->value, in->length);
	return GSS_S_COMPLETE;
}

GSSAPI_LIB_FUNCTION OM_uint32 GSSAPI_LIB_CALL
gss_unwrap(OM_uint32 *min, gss_const_ctx_id_t ctx, const gss_buffer_t in,
	   gss_buffer_t out, int *conf_state, gss_qop_t *qop_state)
{

	*min = 0;
	out->length = in->length;
	out->value = malloc(in->length);
	memcpy(out->value, in->value, in->length);
	return GSS_S_COMPLETE;
}
