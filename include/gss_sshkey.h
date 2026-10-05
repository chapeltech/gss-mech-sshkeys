#ifndef GSS_SSHKEY_H
#define GSS_SSHKEY_H

#include <gssapi/gssapi.h>
#include <stddef.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#define GSS_SSHKEY_CONTEXT_VERSION_1 1

#define GSS_SSHKEY_CONTEXT_CLIENT 1
#define GSS_SSHKEY_CONTEXT_SERVER 2
#define GSS_SSHKEY_CONTEXT_ALL 0xffffffffu

#define GSS_SSHKEY_FIELD_USER "user"
#define GSS_SSHKEY_FIELD_HOST_KEY "host-key"
#define GSS_SSHKEY_FIELD_PEER_ADDRESS "peer-address"

#define GSS_SSHKEY_ARRAY_LEN(array) (sizeof(array) / sizeof((array)[0]))

typedef struct gss_sshkey_context_field {
	const char *name;
	gss_buffer_desc value;
} gss_sshkey_context_field;

/*
 * Stage typed facts for the next context-establishment call on this thread.
 * The mechanism consumes the applicable fields when it creates the context.
 */
OM_uint32 gss_sshkey_set_context_fields(
	OM_uint32 *,
	OM_uint32,
	OM_uint32,
	const gss_sshkey_context_field *,
	size_t);

OM_uint32 gss_sshkey_clear_context_fields(OM_uint32 *, OM_uint32);

static inline gss_sshkey_context_field
gss_sshkey_context_bytes(const char *name, const void *value, size_t length)
{
	gss_sshkey_context_field field;

	field.name = name;
	field.value.length = length;
	field.value.value = (void *)value;
	return field;
}

static inline gss_sshkey_context_field
gss_sshkey_context_string(const char *name, const char *value)
{
	return gss_sshkey_context_bytes(name, value,
	    value == NULL ? 0 : strlen(value));
}

static inline OM_uint32
gss_sshkey_set_client_context(
	OM_uint32 *minor,
	const gss_sshkey_context_field *fields,
	size_t field_count)
{
	return gss_sshkey_set_context_fields(minor, GSS_SSHKEY_CONTEXT_CLIENT,
	    GSS_SSHKEY_CONTEXT_VERSION_1, fields, field_count);
}

static inline OM_uint32
gss_sshkey_set_server_context(
	OM_uint32 *minor,
	const gss_sshkey_context_field *fields,
	size_t field_count)
{
	return gss_sshkey_set_context_fields(minor, GSS_SSHKEY_CONTEXT_SERVER,
	    GSS_SSHKEY_CONTEXT_VERSION_1, fields, field_count);
}

#ifdef __cplusplus
}
#endif

#endif
