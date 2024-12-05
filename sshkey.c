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

#include <krb5.h>

#include "sshkey.h"

/* XXXrcd: shouldn't be here! */
struct gss_name_t_desc_struct {
	void *value;
	unsigned length;
};

typedef unsigned char u8;
int curve25519_donna(u8 *, const u8 *, const u8 *);

/* Internal structure definitions */

/* XXXrcd: sshkey_state isn't used... */
enum sshkey_state {
	  kex_sent
	, kex_done
	, userauth_done
};

typedef struct {
	/* First describe where we are, our state */
	unsigned	  is_initiator	: 1,
			  kex_sent	: 1,	// XXXrcd: do we need this?
			  kex_done	: 1,
			  userauth_done	: 1;

	/*
	 * During KEX, we need to save our secret key.  Once KEX
	 * is complete, we need to store our session key.  We use
	 * the same space as one replaces the other...
	 */

	char		 *keytype;
	uint8_t		 *key;

	/*
	 * Once we are authenticated, we need to have a username
	 * but we shouldn't forget the session key above.
	 */

	char		 *user;

	/*
	 * Keep track of the SSH Keys that we've tried and that
	 * failed to authenticate.
	 */

	char		 *attempting;
	char		**fails;

} *sshkey_ctx;

/*
 * XXXrcd: GBAIL() expects that ...
 * XXXrcd: review *min and gret in GASSERT()
 */

#define GBAIL(x) do {					\
			gret = (x);			\
			if (gret != GSS_S_COMPLETE) 	\
				goto bail;		\
		} while (0)

#define GASSERT(x) do {					\
			if (!(x)) {			\
				(*min) = EINVAL;	\
				gret = GSS_S_FAILURE;	\
				goto bail;		\
			}				\
		} while (0)

/* Local functions */

static OM_uint32
decrypt_ctx(OM_uint32 *min, uint8_t **buf, size_t *len, const EncCtx *ectx)
{

	*buf = malloc(ectx->encPart.length);
	if (!*buf) {
		*min = ENOMEM;
		return GSS_S_FAILURE;
	}

	memcpy(*buf, ectx->encPart.data, ectx->encPart.length);
	return GSS_S_COMPLETE;
}

static OM_uint32
decode_input_token(OM_uint32 *min, const gss_buffer_t in, SshKeyToken *tok,
		   size_t *len)
{

	tok->cctx = NULL;
	tok->sctx = NULL;
	*len = 0;
	if (in->length) {
		decode_SshKeyToken(in->value, in->length, tok, len);
		// XXXrcd: bail on errors
	}
	return GSS_S_COMPLETE;
}

static OM_uint32
decode_context(OM_uint32 *min, sshkey_ctx ctx, const EncCtx *ectx)
{
	OM_uint32	 gret = GSS_S_COMPLETE;
	SshKeyCtx	 actx;
	uint8_t		*buf = NULL;
	size_t		 len;
	int		 ret;

	GBAIL(decrypt_ctx(min, &buf, &len, ectx));
	ret = decode_SshKeyCtx(buf, len, &actx, &len);

	fprintf(stderr, "decode ret = %d\n", ret);

	if (actx.key) {
		if (actx.key->length != 65536) { // XXXrcd: ridiculously big?
			*min = EINVAL;
			gret = GSS_S_FAILURE;
			goto bail;
		}

		ctx->key = malloc(actx.key->length);
		if (!ctx->key) {
			*min = ENOMEM;
			gret = GSS_S_FAILURE;
			goto bail;
		}

		memcpy(ctx->key, actx.key->data, actx.key->length);
	}

bail:
	free(buf);
	free(ctx->key);
	ctx->key = NULL;
	free_SshKeyCtx(&actx);

	return gret;
}

static OM_uint32
unpack_or_create_ctx(OM_uint32 *min, sshkey_ctx *ctx, const EncCtx *ectx)
{

	/* XXXrcd: do we need to call gss_decapsulate_token()? */

	*min = 0;
	/*
	 * If we already have a context, we are finished.  Maybe we should still
	 * unpack it and ensure that it's accurate?  Honestly, we shouldn't be
	 * sending it in the first place if we are keeping the context locally...
	 * It might be an error to find a context if we have one...  A bug, you
	 * know, a bug...
	 */
	if (*ctx)
		return GSS_S_COMPLETE;

	/* XXXrcd: have to decrypt it first, but we skip that for now */
	/* Unpack buf if we have been passed one */
	/* XXXrcd: return if we unpack one */

	/* Otherwise, we create a context */
	*ctx = calloc(1, sizeof(**ctx));
	if (!*ctx) {
		*min = ENOMEM;
		/* XXXrcd: new error... */
		return GSS_S_FAILURE;
	}

	if (ectx)
		decode_context(min, *ctx, ectx);

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
	sshkey_ctx	ctx = (sshkey_ctx)*gctx;
	OM_uint32	gret;
	SshKeyToken	intok;
	SshKeyToken	outtok;
	size_t		len;

	*min = 0;
	output_token->length = 0;
	output_token->value = NULL;

	memset(&intok,  0x0, sizeof(intok));
	memset(&outtok, 0x0, sizeof(outtok));

	if (in)
		GBAIL(decode_input_token(min, in, &intok, &len));
	GBAIL(unpack_or_create_ctx(min, &ctx, intok.cctx));

	if (!in) {
		// XXXrcd: this isn't actually a special case!
		//         the only thing that's funny is: status
		//         and we can just call that GSS_S_CONTINUE_NEEDED!
		//	   But really: we can do that right now!!!

		intok.status = SSH_KEY_CONTINUE_NEEDED;
	}

	/* Start with a little sanity */
	GASSERT(ctx->is_initiator == 1);
	GASSERT(intok.encuserauth == NULL);

	if (intok.status == SSH_KEY_COMPLETE) {
		// check some things
		gret = GSS_S_COMPLETE;
		goto bail;
	}

	gret = GSS_S_CONTINUE_NEEDED;

	// XXXrcd: if we are completely finished, then wtf?

	if (ctx->kex_done) {
		GASSERT(intok.kex == NULL);
		GASSERT(intok.hostauth == NULL);
	}

	if (intok.kex) {
		GASSERT(intok.hostauth != NULL);
		// . validate host signature

		/*
		 * If they didn't like my proposal, null it out and
		 * continue as if I never sent it...
		 */
		/* XXXrcd: intok.kex->kextype->data ignores ->length ??? */
		if (ctx->kex_sent &&
		    ctx->keytype  && strcmp(ctx->keytype,
				            intok.kex->kextype->data)) {
			ctx->kex_sent = 0;
			free(ctx->keytype);
			ctx->keytype = NULL;
		}

		if (!ctx->kex_sent)
			// XXXrcd: encode KEX DER in func below:
			GBAIL(generate_kex_reply());

		/* If we are here, we have agreed a key.*/
		ctx->kex_done = 1;
		GBAIL(set_session_key());
	}

	// XXXrcd: encode userauth DER in below:
	GBAIL(generate_userauth());
#if 0
	uint8_t	basepoint[32] = {9};
	uint8_t	pk[32];
	if (!ctx->key) {
		ctx->key = malloc(32);
		if (!ctx->key) {
			/* XXXrcd: LEAK LEAK LEAK */
			*min = ENOMEM;
			return GSS_S_FAILURE;
		}

		krb5_generate_random_block((*ctx)->secret, 32);
		/* XXXrcd: these bitwise ops are unnecessary? */
		(*ctx)->secret[0]  &= 248;
		(*ctx)->secret[31] &= 127;
		(*ctx)->secret[31] |= 64;

		curve25519_donna((*ctx)->public, (*ctx)->secret, basepoint);
	}

	/*
	 * Let's assume that down here, we are generating a KEX packet.
	 */

	outtok.sctx = intok.sctx;
	outtok.cctx = NULL;		/* XXXrcd: for now, we don't do this */
	outtok.contents.element = choice_SshKeyContents_kex;

	If we have a session key, then generate and send a userauth packet.
	We can do this even if we have a KEX section.

	output_token->length = 6;
	output_token->value = strdup("hello\n");	/* XXXrcd: no no no */
	*gctx = (gss_ctx_id_t)ctx;
#endif

bail:
	// free_SshKeyToken(&intok);
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
	sshkey_ctx	ctx = (sshkey_ctx)*gctx;
	OM_uint32	gret;

	*min = 0;
	output_token->length = 0;
	output_token->value = NULL;

	/* XXXrcd: well... in future, we shouldn't be doing this one... */
	if (in->length != 6)
		return GSS_S_FAILURE;

	// GBAIL(unpack_or_create_ctx(min, &ctx, in));

	if (strcmp(in->value, "hello\n") != 0)
		return GSS_S_FAILURE;

	*src_name = (void *)1;
	gret = GSS_S_COMPLETE;
	*gctx = (gss_ctx_id_t)ctx;
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

	ctx = (sshkey_ctx)*gctx;
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
