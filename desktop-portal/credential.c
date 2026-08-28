/*
 * Copyright © 2025 Isaiah Inuwa <isaiah.inuwa@gmail.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library. If not, see <http://www.gnu.org/licenses/>.
 *
 * Authors:
 *       Isaiah Inuwa <isaiah.inuwa@gmail.com>
 */

#include "credential.h"
#include <sched.h>
#include <sys/types.h>

#include <stdint.h>

#include <gio/gunixfdlist.h>

#include "credentialsd-experimental-dbus.h"
#include "dex-aio.h"
#include "dex-channel.h"
#include "dex-error.h"
#include "gio/gio.h"
#include "glib-object.h"
#include "glib.h"
#include "glibconfig.h"
#include "xdp-app-info.h"
#include "xdp-context.h"
#include "xdp-experimental-dbus.h"
#include "xdp-experimental-handler-dbus.h"
#include "xdp-impl-experimental-dbus.h"
#include "xdp-portal-config.h"
#include "xdp-request-dex.h"
#include "xdp-utils.h"

#define DEFINE_CREDENTIALSD_SIGNAL_CB(signal_name, signal_str, snake_name, ...) \
  static DexFuture *                                                                               \
  snake_name##_fiber (gpointer user_data)                                                          \
  {                                                                                                \
    g_autoptr (XdpCredential) credential = NULL;                                                   \
    g_autoptr (DexPromise) promise = NULL;                                                         \
    g_autoptr (GError) error = NULL;                                                               \
                                                                                                   \
    {                                                                                              \
      g_autofree XdpCredentialResponsePromise *response_promise = g_steal_pointer (&user_data);    \
      credential = g_steal_pointer (&response_promise->credential);                                \
      promise = g_steal_pointer (&response_promise->promise);                                       \
    }                                                                                              \
    g_autoptr (CredentialsdDbusExperimentalSessionSignalMonitor) signal_monitor =                  \
      g_object_ref (credential->credsd_signal_monitor);                                            \
    g_autoptr (DexChannel) channel = dex_ref (signal_monitor->snake_name##_channel);               \
                                                                                                   \
    while (channel != NULL && dex_channel_can_receive(channel))                                    \
      {                                                                                            \
        g_autoptr (CredentialsdDbusExperimentalSession##signal_name##Signal) signal = NULL;        \
        signal = dex_await_boxed (credentialsd_dbus_experimental_session_signal_monitor_next_##snake_name ( \
            credential->credsd_signal_monitor                                                      \
          ),                                                                                       \
          &error                                                                                   \
        );                                                                                         \
                                                                                                   \
        if (error)                                                                                 \
          {                                                                                        \
            if (error->domain == dex_error_quark() && error->code == DEX_ERROR_CHANNEL_CLOSED)     \
            {                                                                                      \
              return dex_future_new_true ();                                                       \
            }                                                                                      \
            g_warning("Failed to receive " signal_str ": %s (%d)", error->message, error->code);   \
            return dex_future_new_false ();                                                        \
          }                                                                                        \
        g_debug("Received " signal_str " from credentialsd");                                      \
                                                                                                   \
        XdpDbusExperimentalImplCredential *impl = credential->impl;                                \
        if (!dex_await (xdp_dbus_experimental_impl_credential_call_notify_##snake_name##_future (  \
            impl,                                                                                  \
            credential->backend_session_id,                                                        \
            __VA_ARGS__                                                                            \
          ),                                                                                       \
          &error))                                                                                 \
          {                                                                                        \
            g_warning ("Failed to send " signal_str ": %s (%d)", error->message, error->code);     \
          }                                                                                        \
      }                                                                                            \
    return dex_future_new_true ();                                                                 \
  }                                                                                                \


enum CredentialOperation {
  CREDENTIAL_OPERATION_PUBLIC_KEY_CREATE = 0,
  CREDENTIAL_OPERATION_PUBLIC_KEY_GET = 1,
};

static gboolean handle_create_credential (XdpDbusExperimentalCredential *object,
                                          GDBusMethodInvocation *invocation,
                                          const gchar *arg_parent_window,
                                          const gchar *arg_origin,
                                          const gchar *arg_type,
                                          GVariant *arg_options);

static gboolean handle_get_credential (XdpDbusExperimentalCredential *object,
                                       GDBusMethodInvocation *invocation,
                                       const gchar *arg_parent_window,
                                       const gchar *arg_origin,
                                       GVariant *arg_options);

struct _XdpCredential
{
  XdpDbusExperimentalCredentialSkeleton parent_instance;

  XdpContext *context;
  XdpDbusExperimentalHandlerCredential *handler;
  XdpDbusExperimentalImplCredential *impl;
  XdpDbusExperimentalImplCredentialSignalMonitor *impl_signal_monitor;
  CredentialsdDbusExperimentalManager *manager;

  // May be null
  CredentialsdDbusExperimentalSession *credsd_session;
  CredentialsdDbusExperimentalSessionSignalMonitor *credsd_signal_monitor;
  gchar *backend_session_id;
};

#define XDP_TYPE_CREDENTIAL (xdp_dbus_experimental_credential_get_type ())
G_DECLARE_FINAL_TYPE (XdpCredential, xdp_credential, XDP, CREDENTIAL, XdpDbusExperimentalCredentialSkeleton)

static void
xdp_credential_iface_init (XdpDbusExperimentalCredentialIface *iface);

G_DEFINE_FINAL_TYPE_WITH_CODE (
    XdpCredential,
    xdp_credential,
    XDP_DBUS_EXPERIMENTAL_TYPE_CREDENTIAL_SKELETON,
    G_IMPLEMENT_INTERFACE (XDP_DBUS_EXPERIMENTAL_TYPE_CREDENTIAL, xdp_credential_iface_init)
  );

static void xdp_credential_iface_init (XdpDbusExperimentalCredentialIface *iface)
{
  iface->handle_create_credential = handle_create_credential;
  iface->handle_get_credential = handle_get_credential;
}

static void xdp_credential_dispose (GObject *object)
{
  XdpCredential *credential = XDP_CREDENTIAL (object);

  g_clear_object (&credential->handler);
  g_clear_object (&credential->impl);
  g_clear_object (&credential->impl_signal_monitor);
  g_clear_object (&credential->manager);

  G_OBJECT_CLASS (xdp_credential_parent_class)->dispose (object);
}

static void xdp_credential_init (XdpCredential *credential) {}

static void xdp_credential_class_init (XdpCredentialClass *klass)
{
  GObjectClass *object_class = G_OBJECT_CLASS (klass);

  object_class->dispose = xdp_credential_dispose;
}

static XdpCredential *
xdp_credential_new(XdpContext *context,
                   XdpDbusExperimentalImplCredential *impl,
                   XdpDbusExperimentalImplCredentialSignalMonitor *impl_signal_monitor,
                   CredentialsdDbusExperimentalManager *manager,
                   XdpDbusExperimentalHandlerCredential *handler)
{
  XdpCredential *credential;

  credential = g_object_new(xdp_credential_get_type(), NULL);
  credential->context = context;
  credential->impl = g_object_ref(impl);
  credential->impl_signal_monitor = g_object_ref(impl_signal_monitor);
  credential->manager = g_object_ref(manager);
  credential->handler = g_object_ref(handler);

  g_dbus_proxy_set_default_timeout (G_DBUS_PROXY (credential->handler), G_MAXINT);

  xdp_dbus_experimental_credential_set_conditional_create (
      XDP_DBUS_EXPERIMENTAL_CREDENTIAL (credential), FALSE);
  xdp_dbus_experimental_credential_set_conditional_get (
      XDP_DBUS_EXPERIMENTAL_CREDENTIAL (credential), FALSE);
  xdp_dbus_experimental_credential_set_hybrid_transport (
      XDP_DBUS_EXPERIMENTAL_CREDENTIAL (credential), TRUE);
  xdp_dbus_experimental_credential_set_passkey_platform_authenticator (
      XDP_DBUS_EXPERIMENTAL_CREDENTIAL (credential), TRUE);
  xdp_dbus_experimental_credential_set_user_verifying_platform_authenticator (
      XDP_DBUS_EXPERIMENTAL_CREDENTIAL (credential), FALSE);
  xdp_dbus_experimental_credential_set_related_origins (
      XDP_DBUS_EXPERIMENTAL_CREDENTIAL (credential), TRUE);
  xdp_dbus_experimental_credential_set_signal_all_accepted_credentials (
      XDP_DBUS_EXPERIMENTAL_CREDENTIAL (credential), FALSE);
  xdp_dbus_experimental_credential_set_signal_current_user_details (
      XDP_DBUS_EXPERIMENTAL_CREDENTIAL (credential), FALSE);
  xdp_dbus_experimental_credential_set_signal_unknown_credential (
      XDP_DBUS_EXPERIMENTAL_CREDENTIAL (credential), FALSE);

  xdp_dbus_experimental_credential_set_version (
      XDP_DBUS_EXPERIMENTAL_CREDENTIAL (credential), 1);

  return credential;
}

typedef struct XdpCredentialResponsePromise
{
  XdpCredential *credential;
  DexPromise *promise;
} XdpCredentialResponsePromise;

GQuark quark_credentialsd_error;

const gchar *CREDENTIALSD_HANDLER_DBUS_NAME =
    "xyz.iinuwa.credentialsd.Credentials";

const gchar *CREDENTIALSD_DBUS_NAME =
    "xyz.iinuwa.credentialsd.Credentials";

DEFINE_CREDENTIALSD_SIGNAL_CB(
  NeedsPin, "NeedsPin", needs_pin, signal->attempts_left, signal->_options)


DEFINE_CREDENTIALSD_SIGNAL_CB(NeedsUserVerification,
                              "NeedsUserVerification",
                              needs_user_verification,
                              signal->attempts_left,
                              signal->_options)

DEFINE_CREDENTIALSD_SIGNAL_CB(
    NeedsUserPresence, "NeedsUserPresence", needs_user_presence, signal->_options)

DEFINE_CREDENTIALSD_SIGNAL_CB(SelectingCredential,
                              "SelectingCredential",
                              selecting_credential,
                              signal->credentials,
                              signal->_options)

static DexFuture *
hybrid_started_fiber(gpointer user_data)
{
  g_autoptr (XdpCredential) credential = NULL;
  g_autoptr (DexPromise) promise = NULL;
  g_autoptr (GError) error = NULL;

  {
    g_autofree XdpCredentialResponsePromise *response_promise = g_steal_pointer (&user_data);
    credential = response_promise->credential;
    promise = response_promise->promise;
  }

  g_autoptr (CredentialsdDbusExperimentalSessionSignalMonitor)  signal_monitor = g_object_ref (credential->credsd_signal_monitor);
  g_autoptr (DexChannel) channel = dex_ref (signal_monitor->hybrid_started_channel);
  while (channel != NULL && dex_channel_can_receive(channel))
    {
      g_autoptr (CredentialsdDbusExperimentalSessionHybridStartedSignal) signal = NULL;
      signal = dex_await_boxed (credentialsd_dbus_experimental_session_signal_monitor_next_hybrid_started (
          credential->credsd_signal_monitor
        ),
        &error
      );

      if (error)
        {
          if (error->domain == dex_error_quark() && error->code == DEX_ERROR_CHANNEL_CLOSED)
          {
            return dex_future_new_true ();
          }

          g_warning("Failed to receive HybridStarted: %s (%d)", error->message, error->code);
          return dex_future_new_false ();
        }
      g_debug("Received HybridStarted from credentialsd");

      g_autoptr(GUnixFDList) fd_list = g_unix_fd_list_new();

      g_autoptr (CredentialsdDbusExperimentalSessionGetHybridInvocationDataResult) invocation_data_result = NULL;
      invocation_data_result = dex_await_boxed (credentialsd_dbus_experimental_session_call_get_hybrid_invocation_data_future (credential->credsd_session, fd_list), &error);
      if (!invocation_data_result)
      {
        // TODO: shutdown
        g_warning("Could not retrieve hybrid invocation data fd: %s (%d)", error->message, error->code);
        return dex_future_new_false ();
      }

      XdpDbusExperimentalImplCredential *impl = credential->impl;
      gboolean notified = dex_await (xdp_dbus_experimental_impl_credential_call_notify_hybrid_started_future (
          impl,
          credential->backend_session_id,
          invocation_data_result->invocation_data,
          signal->_options,
          invocation_data_result->fd_list
        ),
        &error);
      if (!notified)
          g_warning ("Failed to send HybridStarted: %s (%d)", error->message, error->code);
    }
  return dex_future_new_true ();
}

DEFINE_CREDENTIALSD_SIGNAL_CB(HybridConnecting, "HybridConnecting", hybrid_connecting, signal->_options)

DEFINE_CREDENTIALSD_SIGNAL_CB(HybridConnected, "HybridConnected", hybrid_connected, signal->_options)

DEFINE_CREDENTIALSD_SIGNAL_CB(NfcConnected, "NfcConnected", nfc_connected, signal->_options)

DEFINE_CREDENTIALSD_SIGNAL_CB(UsbConnected, "UsbConnected", usb_connected, signal->_options)

static DexFuture *
ceremony_completed_fiber(gpointer user_data)
{
  g_autoptr (XdpCredential) credential = NULL;
  g_autoptr (DexPromise) promise = NULL;
  g_autoptr (GError) error = NULL;
  {
    g_autofree XdpCredentialResponsePromise *response_promise = g_steal_pointer (&user_data);
    credential = g_steal_pointer (&response_promise->credential);
    promise = g_steal_pointer (&response_promise->promise);
  }

  g_autoptr (CredentialsdDbusExperimentalSessionSignalMonitor)  signal_monitor = g_object_ref (credential->credsd_signal_monitor);
  g_autoptr (DexChannel) channel = dex_ref (signal_monitor->ceremony_completed_channel);

  while (channel != NULL && dex_channel_can_receive(channel))
    {
      g_autoptr (CredentialsdDbusExperimentalSessionCeremonyCompletedSignal) signal = NULL;
      signal = dex_await_boxed (credentialsd_dbus_experimental_session_signal_monitor_next_ceremony_completed (
          credential->credsd_signal_monitor
        ),
        &error
      );

      if (error != NULL)
        {
          if (error->domain == dex_error_quark() && error->code == DEX_ERROR_CHANNEL_CLOSED)
          {
            return dex_future_new_true ();
          }

          g_warning("Failed to receive CeremonyCompleted: %s (%d)", error->message, error->code);
          dex_promise_reject (promise, g_steal_pointer(&error));
          return dex_future_new_false ();
        }

      g_info("Received CeremonyCompleted");
      XdpDbusExperimentalImplCredential *impl = credential->impl;
      gboolean notified = dex_await (xdp_dbus_experimental_impl_credential_call_notify_ceremony_completed_future (
          impl,
          credential->backend_session_id
        ),
        &error);
      if (!notified)
          g_warning("Failed to send CeremonyCompleted %s (%d)", error->message, error->code);
      // Do we have ownership over the response?
      dex_promise_resolve_variant (promise, g_variant_ref (signal->response));
    }
    return dex_future_new_true();
}

static DexFuture *
error_occurred_fiber(gpointer user_data)
{
  g_autoptr (XdpCredential) credential = NULL;
  g_autoptr (DexPromise) promise = NULL;
  g_autoptr (GError) error = NULL;

  {
    g_autofree XdpCredentialResponsePromise *response_promise = g_steal_pointer (&user_data);
    credential = g_steal_pointer (&response_promise->credential);
    promise = g_steal_pointer (&response_promise->promise);
  }

  g_autoptr (CredentialsdDbusExperimentalSessionSignalMonitor)  signal_monitor = g_object_ref (credential->credsd_signal_monitor);
  g_autoptr (DexChannel) channel = dex_ref (signal_monitor->error_occurred_channel);

  while (channel != NULL && dex_channel_can_receive(channel))
    {
      g_autoptr (CredentialsdDbusExperimentalSessionErrorOccurredSignal) signal = NULL;
      signal = dex_await_boxed (credentialsd_dbus_experimental_session_signal_monitor_next_error_occurred (
          credential->credsd_signal_monitor
        ),
        &error
      );

      if (error != NULL)
        {
          if (error->domain == dex_error_quark() && error->code == DEX_ERROR_CHANNEL_CLOSED)
          {
            return dex_future_new_true ();
          }

          g_warning("Failed to receive ErrorOccurred: %s (%d)", error->message, error->code);
          dex_promise_reject (promise, g_steal_pointer(&error));
          return dex_future_new_false ();
        }

      g_debug("Received ErrorOccurred");
      XdpDbusExperimentalImplCredential *impl = credential->impl;
      gboolean notified = dex_await (xdp_dbus_experimental_impl_credential_call_notify_error_occurred_future (
            impl, credential->backend_session_id, signal->error), &error);
      if (!notified)
          g_warning("Failed to send ErrorOccurred %s (%d)", error->message, error->code);
      g_set_error(&error, quark_credentialsd_error, signal->error, "credentialsd session returned an error");
      // Do we have ownership over the response?
      dex_promise_reject (promise, g_steal_pointer(&error));
    }

    return dex_future_new_true();
}

static XdpOptionKey create_credential_options[] = {
  { "handle_token", G_VARIANT_TYPE_STRING, NULL },
  { "origin", G_VARIANT_TYPE_STRING, NULL },
  { "top_origin", G_VARIANT_TYPE_STRING, NULL },
  { "type", G_VARIANT_TYPE_STRING, NULL },
  { "public_key", G_VARIANT_TYPE_STRING, NULL },
};

/**
 * create_credential_validate_options:
 * @arg_options: (transfer none): options passed to the frontend.
 * @arg_type: (transfer none): options passed to the frontend.
 * @frontend_options: (transfer none): options passed to the frontend.
 * @backend_options: (transfer none): options passed to the frontend.
 * @request_json: (transfer none): pointer to string to be filled with request JSON.
 * @top_origin: (transfer none): pointer to string to top_origin field. May be NULL.
 * @error: (transfer none): pointer to an error pointer that will be populated on error.
 * Returns: (transfer full): Filtered list of options to pass to the handler.
 */
static gboolean
create_credential_validate_options (GVariant *arg_options,
                                    const gchar *arg_type,
                                    GVariant **frontend_options,
                                    GVariantDict **backend_options,
                                    gchar **request_json,
                                    gchar **top_origin,
                                    GError **error)
{
  g_auto (GVariantBuilder) options =
      G_VARIANT_BUILDER_INIT (G_VARIANT_TYPE_VARDICT);
  g_autofree gchar *json = NULL;
  g_autofree gchar *top_origin_tmp = NULL;
  g_autoptr (GVariantDict) backend_options_dict = NULL;

  if (!xdp_filter_options (arg_options,
                           &options,
                           create_credential_options,
                           G_N_ELEMENTS (create_credential_options),
                           NULL,
                           error))
    {
      return FALSE;
    }

  if (g_strcmp0 (arg_type, "publicKey") != 0)
    {
      g_set_error (error,
                   XDG_DESKTOP_PORTAL_ERROR,
                   XDG_DESKTOP_PORTAL_ERROR_INVALID_ARGUMENT,
                   "Invalid credential type: `%s`. Supported types [`publicKey`]", arg_type);
      return FALSE;
    }

  if (!g_variant_lookup (arg_options, "public_key", "s", &json))
    {
      g_set_error (error,
                   XDG_DESKTOP_PORTAL_ERROR,
                   XDG_DESKTOP_PORTAL_ERROR_INVALID_ARGUMENT,
                   "`public_key` option is required when `publicKey` credential type is requested");
      return FALSE;
    };

  {
    backend_options_dict = g_variant_dict_new (NULL);

    gchar *activation_token = "";
    // TODO: I don't think this else statement is necessary; check bug in credentialsd
    if (g_variant_lookup (arg_options, "activation_token", "s", activation_token))
      g_variant_dict_insert (backend_options_dict, "activation_token", "s", activation_token);
    else
      g_variant_dict_insert (backend_options_dict, "activation_token", "s", "");

    if (!g_variant_lookup (arg_options, "top_origin", "s", &top_origin_tmp))
      top_origin_tmp = g_strdup ("");
    g_variant_dict_insert (backend_options_dict, "top_origin", "s", top_origin_tmp);
  }

  *frontend_options = g_variant_ref_sink (g_variant_builder_end (&options));
  *backend_options = g_steal_pointer (&backend_options_dict);
  *request_json = g_steal_pointer (&json);
  *top_origin = g_steal_pointer (&top_origin_tmp);
  return TRUE;
}


/**
 * Fiber functions to be used during a create or get credential request.
 */
static DexFiberFunc public_key_credential_fibers[] = {
  needs_pin_fiber,
  needs_user_verification_fiber,
  needs_user_presence_fiber,
  hybrid_started_fiber,
  hybrid_connecting_fiber,
  hybrid_connected_fiber,
  nfc_connected_fiber,
  usb_connected_fiber,
  selecting_credential_fiber,
  ceremony_completed_fiber,
  error_occurred_fiber
};

static gboolean handle_create_credential (XdpDbusExperimentalCredential *object,
                                          GDBusMethodInvocation         *invocation,
                                          const gchar                   *arg_parent_window,
                                          const gchar                   *arg_origin,
                                          const gchar                   *arg_type,
                                          GVariant                      *arg_options)
{
  XdpCredential *credential = XDP_CREDENTIAL (object);
  g_autoptr (XdpRequestDex) request = NULL;
  g_autoptr (GError) error = NULL;
  g_autoptr (GVariant) frontend_options = NULL;
  g_autoptr (GVariantDict) backend_options_dict = NULL;
  g_autofree gchar *request_json = NULL;
  g_autofree gchar *top_origin = NULL;
  g_autofree gchar *daemon_session_handle = NULL;


  XdpAppInfo *app_info = xdp_invocation_get_app_info (invocation);
  const gchar *app_id = xdp_app_info_get_id (app_info);

  gboolean is_validated = create_credential_validate_options (arg_options,
                                                              arg_type,
                                                              &frontend_options,
                                                              &backend_options_dict,
                                                              &request_json,
                                                              &top_origin,
                                                              &error);

  if (!is_validated)
    {
      g_dbus_method_invocation_return_gerror (g_steal_pointer (&invocation), error);
      return G_DBUS_METHOD_INVOCATION_HANDLED;
    }

  request = dex_await_object (xdp_request_dex_new (
        credential->context,
        app_info,
        G_DBUS_INTERFACE_SKELETON (object),
        G_DBUS_PROXY (credential->impl),
        frontend_options
    ),
    &error);
  if (!request)
    {
      g_dbus_method_invocation_return_gerror (g_steal_pointer (&invocation), error);
      return G_DBUS_METHOD_INVOCATION_HANDLED;
    }

  xdp_dbus_experimental_credential_complete_create_credential (
      object,
      invocation,
      xdp_request_dex_get_object_path (request));

  {
    g_autoptr (XdpDbusExperimentalHandlerCredentialCreateCredentialResult) result = NULL;
    g_autoptr (CredentialsdDbusExperimentalSession) credsd_session = NULL;
    g_autoptr (CredentialsdDbusExperimentalSessionSignalMonitor) credsd_signal_monitor = NULL;

    {
      g_autoptr (CredentialsdDbusExperimentalManagerCreatePublicKeyCredentialResult) daemon_session_result = NULL;
      GDBusConnection *connection = xdp_context_get_connection (credential->context);
      daemon_session_result = dex_await_boxed (credentialsd_dbus_experimental_manager_call_create_public_key_credential_future (
          credential->manager,
          request_json,
          arg_origin,
          top_origin
        ),
        &error);
      if (daemon_session_result == NULL)
        {
          g_warning ("Failed to create proxy for credentialsd session: %s (%d)", error->message, error->code);
          xdp_request_dex_emit_response (request,
                                        XDG_DESKTOP_PORTAL_RESPONSE_OTHER,
                                        NULL);
          return G_DBUS_METHOD_INVOCATION_HANDLED;
        }
      credsd_session = dex_await_object (credentialsd_dbus_experimental_session_proxy_new_future (
          connection,
          G_DBUS_PROXY_FLAGS_NONE,
          CREDENTIALSD_DBUS_NAME,
          daemon_session_result->session_handle
        ), &error);
      if (credsd_session == NULL)
        {
          g_warning ("Failed to create proxy for credentialsd session: %s (%d)", error->message, error->code);
          xdp_request_dex_emit_response (request, XDG_DESKTOP_PORTAL_RESPONSE_OTHER, NULL);
          return G_DBUS_METHOD_INVOCATION_HANDLED;
        }
        credential->credsd_session = g_steal_pointer (&credsd_session);
        daemon_session_handle = g_strdup (daemon_session_result->session_handle);
    }

    GVariant *devices = credentialsd_dbus_experimental_session_get_devices (credential->credsd_session);

    g_variant_dict_insert (
        backend_options_dict,
        "rp_id",
        "s",
        credentialsd_dbus_experimental_session_get_rp_id (credential->credsd_session));
    g_autoptr (GVariant) backend_options = g_variant_ref_sink (g_variant_dict_end (
        g_steal_pointer (&backend_options_dict)));

    // TODO: Make this conform to normal session naming convention.
    credential->backend_session_id = g_steal_pointer (&daemon_session_handle);
    // TODO: Remove this from backend.
    int pid = -1;

    if (!dex_await (xdp_dbus_experimental_impl_credential_call_create_session_future (
        credential->impl,
        credential->backend_session_id,
        arg_parent_window,
        arg_origin,
        CREDENTIAL_OPERATION_PUBLIC_KEY_CREATE,
        devices,
        app_id,
        pid,
        backend_options
      ),
      &error)
    )
      {
        g_warning ("Failed to create backend session: %s (%d)", error->message, error->code);
        xdp_request_dex_emit_response (request,
                                      XDG_DESKTOP_PORTAL_RESPONSE_OTHER,
                                      NULL);
        return G_DBUS_METHOD_INVOCATION_HANDLED;
      }

    g_autoptr (DexPromise) promise = dex_promise_new();

    CredentialsdDbusExperimentalSessionSignals signals =
      CREDENTIALSD_DBUS_EXPERIMENTAL_SESSION_SIGNAL_NEEDS_PIN
      | CREDENTIALSD_DBUS_EXPERIMENTAL_SESSION_SIGNAL_NEEDS_USER_VERIFICATION
      | CREDENTIALSD_DBUS_EXPERIMENTAL_SESSION_SIGNAL_NEEDS_USER_PRESENCE
      | CREDENTIALSD_DBUS_EXPERIMENTAL_SESSION_SIGNAL_HYBRID_STARTED
      | CREDENTIALSD_DBUS_EXPERIMENTAL_SESSION_SIGNAL_HYBRID_CONNECTING
      | CREDENTIALSD_DBUS_EXPERIMENTAL_SESSION_SIGNAL_HYBRID_CONNECTED
      | CREDENTIALSD_DBUS_EXPERIMENTAL_SESSION_SIGNAL_NFC_CONNECTED
      | CREDENTIALSD_DBUS_EXPERIMENTAL_SESSION_SIGNAL_USB_CONNECTED
      | CREDENTIALSD_DBUS_EXPERIMENTAL_SESSION_SIGNAL_SELECTING_CREDENTIAL
      | CREDENTIALSD_DBUS_EXPERIMENTAL_SESSION_SIGNAL_CEREMONY_COMPLETED
      | CREDENTIALSD_DBUS_EXPERIMENTAL_SESSION_SIGNAL_ERROR_OCCURRED;
    credsd_signal_monitor =
      credentialsd_dbus_experimental_session_signal_monitor_new(credential->credsd_session, signals);
    credential->credsd_signal_monitor = g_object_ref (credsd_signal_monitor);

    DexFuture *signal_handlers[G_N_ELEMENTS (public_key_credential_fibers)];
    for (int i = 0; i < G_N_ELEMENTS (public_key_credential_fibers); i++)
      {
        XdpCredentialResponsePromise *response_promise = g_new0(XdpCredentialResponsePromise, 1);
        response_promise->credential = g_object_ref (credential);
        response_promise->promise = dex_ref (promise);
        DexFiberFunc fiber = public_key_credential_fibers[i];
        signal_handlers[i] = dex_scheduler_spawn (NULL, 0, fiber, response_promise, NULL);
      }

    g_autoptr (GVariant) credential_response = dex_await_variant (dex_ref (DEX_FUTURE (promise)), &error);
    if (error != NULL)
      {
        g_warning ("Failed to get response for create credential: %s (%d)", error->message, error->code);
        xdp_request_dex_emit_response (request, XDG_DESKTOP_PORTAL_RESPONSE_OTHER, NULL);
      }
    else
      {
        xdp_request_dex_emit_response (request,
                                      XDG_DESKTOP_PORTAL_RESPONSE_SUCCESS,
                                      credential_response);
      }

    credentialsd_dbus_experimental_session_signal_monitor_cancel (credential->credsd_signal_monitor);
    dex_await (dex_future_allv (signal_handlers, G_N_ELEMENTS (public_key_credential_fibers)), &error);
    if (error != NULL)
      {
        g_warning ("Failed waiting for credentialsd signal handlers to complete: %s (%d)", error->message, error->code);
      }
    g_clear_pointer (&credential->backend_session_id, g_free);
    g_clear_object (&credential->credsd_session);
    g_clear_object (&credential->credsd_signal_monitor);
  }

  return G_DBUS_METHOD_INVOCATION_HANDLED;
}

static XdpOptionKey get_credential_options[] = {
  { "handle_token", G_VARIANT_TYPE_STRING, NULL },
  { "origin", G_VARIANT_TYPE_STRING, NULL },
  { "top_origin", G_VARIANT_TYPE_STRING, NULL },
  { "public_key", G_VARIANT_TYPE_STRING, NULL },
};

/**
 * get_credential_validate_options:
 * @arg_options: (transfer none): options passed to the frontend.
 * @arg_type: (transfer none): options passed to the frontend.
 * @frontend_options: (transfer none): options passed to the frontend.
 * @backend_options: (transfer none): options passed to the frontend.
 * @request_json: (transfer none): pointer to string to be filled with request JSON.
 * @top_origin: (transfer none): pointer to string to top_origin field. May be NULL.
 * @error: (transfer none): pointer to an error pointer that will be populated on error.
 * Returns: (transfer full): Filtered list of options to pass to the handler.
 */
static gboolean
get_credential_validate_options (GVariant *arg_options,
                                 GVariant **frontend_options,
                                 GVariantDict **backend_options,
                                 gchar **request_json,
                                 gchar **top_origin,
                                 GError **error)
{
  g_auto (GVariantBuilder) options =
      G_VARIANT_BUILDER_INIT (G_VARIANT_TYPE_VARDICT);
  g_autofree gchar *json = NULL;
  g_autofree gchar *top_origin_tmp = NULL;
  g_autoptr (GVariantDict) backend_options_dict = NULL;

  if (!xdp_filter_options (arg_options,
                           &options,
                           get_credential_options,
                           G_N_ELEMENTS (get_credential_options),
                           NULL,
                           error))
    {
      return FALSE;
    }

  if (!g_variant_lookup (arg_options, "public_key", "s", &json))
    {
      g_set_error (error,
                   XDG_DESKTOP_PORTAL_ERROR,
                   XDG_DESKTOP_PORTAL_ERROR_INVALID_ARGUMENT,
                   "Parameters for at least one credential type must be passed in `options` when retrieving a "
                   "credential. Current supported credential types are: `public_key`");
      return FALSE;
    };

  {
    backend_options_dict = g_variant_dict_new (NULL);

    gchar *activation_token = "";
    // TODO: I don't think this else statement is necessary; check bug in credentialsd
    if (g_variant_lookup (arg_options, "activation_token", "s", activation_token))
      g_variant_dict_insert (backend_options_dict, "activation_token", "s", activation_token);
    else
      g_variant_dict_insert (backend_options_dict, "activation_token", "s", "");

    if (!g_variant_lookup (arg_options, "top_origin", "s", &top_origin_tmp))
      top_origin_tmp = g_strdup ("");
    g_variant_dict_insert (backend_options_dict, "top_origin", "s", top_origin_tmp);
  }

  *frontend_options = g_variant_ref_sink (g_variant_builder_end (&options));
  *backend_options = g_steal_pointer (&backend_options_dict);
  *request_json = g_steal_pointer (&json);
  *top_origin = g_steal_pointer (&top_origin_tmp);
  return TRUE;
}

static gboolean handle_get_credential (XdpDbusExperimentalCredential *object,
                                       GDBusMethodInvocation         *invocation,
                                       const gchar                   *arg_parent_window,
                                       const gchar                   *arg_origin,
                                       GVariant                      *arg_options)
{
  XdpCredential *credential = XDP_CREDENTIAL (object);
  g_autoptr (XdpRequestDex) request = NULL;
  g_autoptr (GError) error = NULL;
  g_autoptr (GVariant) frontend_options = NULL;
  g_autoptr (GVariantDict) backend_options_dict = NULL;
  g_autofree gchar *request_json = NULL;
  g_autofree gchar *top_origin = NULL;
  g_autofree gchar *daemon_session_handle = NULL;


  XdpAppInfo *app_info = xdp_invocation_get_app_info (invocation);
  const gchar *app_id = xdp_app_info_get_id (app_info);

  gboolean is_validated = get_credential_validate_options (arg_options,
                                                           &frontend_options,
                                                           &backend_options_dict,
                                                           &request_json,
                                                           &top_origin,
                                                           &error);

  if (!is_validated)
    {
      g_dbus_method_invocation_return_gerror (g_steal_pointer (&invocation), error);
      return G_DBUS_METHOD_INVOCATION_HANDLED;
    }

  request = dex_await_object (xdp_request_dex_new (
        credential->context,
        app_info,
        G_DBUS_INTERFACE_SKELETON (object),
        G_DBUS_PROXY (credential->impl),
        frontend_options
    ),
    &error);
  if (!request)
    {
      g_dbus_method_invocation_return_gerror (g_steal_pointer (&invocation), error);
      return G_DBUS_METHOD_INVOCATION_HANDLED;
    }

  xdp_dbus_experimental_credential_complete_get_credential (
      object,
      invocation,
      xdp_request_dex_get_object_path (request));

  {
    g_autoptr (XdpDbusExperimentalHandlerCredentialGetCredentialResult) result = NULL;
    g_autoptr (CredentialsdDbusExperimentalSession) credsd_session = NULL;
    g_autoptr (CredentialsdDbusExperimentalSessionSignalMonitor) credsd_signal_monitor = NULL;

    {
      g_autoptr (CredentialsdDbusExperimentalManagerGetCredentialResult) daemon_session_result = NULL;
      GDBusConnection *connection = xdp_context_get_connection (credential->context);
      daemon_session_result = dex_await_boxed (credentialsd_dbus_experimental_manager_call_get_credential_future (
          credential->manager,
          arg_origin,
          top_origin,
          frontend_options
        ),
        &error);
      if (daemon_session_result == NULL)
        {
          g_warning ("Failed to create proxy for credentialsd session on GetCredential: %s (%d)", error->message, error->code);
          xdp_request_dex_emit_response (request,
                                        XDG_DESKTOP_PORTAL_RESPONSE_OTHER,
                                        NULL);
          goto out;
        }
      credsd_session = dex_await_object (credentialsd_dbus_experimental_session_proxy_new_future (
          connection,
          G_DBUS_PROXY_FLAGS_NONE,
          CREDENTIALSD_DBUS_NAME,
          daemon_session_result->session_handle
        ), &error);
      if (credsd_session == NULL)
        {
          g_warning ("Failed to create proxy for credentialsd session: %s (%d)", error->message, error->code);
          xdp_request_dex_emit_response (request, XDG_DESKTOP_PORTAL_RESPONSE_OTHER, NULL);
          goto out;
        }
        credential->credsd_session = g_steal_pointer (&credsd_session);
        daemon_session_handle = g_strdup (daemon_session_result->session_handle);
    }

    GVariant *devices = credentialsd_dbus_experimental_session_get_devices (credential->credsd_session);

    g_variant_dict_insert (
        backend_options_dict,
        "rp_id",
        "s",
        credentialsd_dbus_experimental_session_get_rp_id (credential->credsd_session));
    g_autoptr (GVariant) backend_options = g_variant_ref_sink (g_variant_dict_end (
        g_steal_pointer (&backend_options_dict)));

    // TODO: Make this conform to normal session naming convention.
    credential->backend_session_id = g_steal_pointer (&daemon_session_handle);
    // TODO: Remove this from backend.
    int pid = -1;

    if (!dex_await (xdp_dbus_experimental_impl_credential_call_create_session_future (
        credential->impl,
        credential->backend_session_id,
        arg_parent_window,
        arg_origin,
        CREDENTIAL_OPERATION_PUBLIC_KEY_GET,
        devices,
        app_id,
        pid,
        backend_options
      ),
      &error)
    )
      {
        g_warning ("Failed to create backend session: %s (%d)", error->message, error->code);
        xdp_request_dex_emit_response (request,
                                      XDG_DESKTOP_PORTAL_RESPONSE_OTHER,
                                      NULL);
        goto out;
      }

    g_autoptr (DexPromise) promise = dex_promise_new();

    CredentialsdDbusExperimentalSessionSignals signals =
      CREDENTIALSD_DBUS_EXPERIMENTAL_SESSION_SIGNAL_NEEDS_PIN
      | CREDENTIALSD_DBUS_EXPERIMENTAL_SESSION_SIGNAL_NEEDS_USER_VERIFICATION
      | CREDENTIALSD_DBUS_EXPERIMENTAL_SESSION_SIGNAL_NEEDS_USER_PRESENCE
      | CREDENTIALSD_DBUS_EXPERIMENTAL_SESSION_SIGNAL_HYBRID_STARTED
      | CREDENTIALSD_DBUS_EXPERIMENTAL_SESSION_SIGNAL_HYBRID_CONNECTING
      | CREDENTIALSD_DBUS_EXPERIMENTAL_SESSION_SIGNAL_HYBRID_CONNECTED
      | CREDENTIALSD_DBUS_EXPERIMENTAL_SESSION_SIGNAL_NFC_CONNECTED
      | CREDENTIALSD_DBUS_EXPERIMENTAL_SESSION_SIGNAL_USB_CONNECTED
      | CREDENTIALSD_DBUS_EXPERIMENTAL_SESSION_SIGNAL_SELECTING_CREDENTIAL
      | CREDENTIALSD_DBUS_EXPERIMENTAL_SESSION_SIGNAL_CEREMONY_COMPLETED
      | CREDENTIALSD_DBUS_EXPERIMENTAL_SESSION_SIGNAL_ERROR_OCCURRED;
    credsd_signal_monitor =
      credentialsd_dbus_experimental_session_signal_monitor_new(credential->credsd_session, signals);
    credential->credsd_signal_monitor = g_object_ref (credsd_signal_monitor);

    /**
     * we pass a reference to the Credential object and the promise to each
     * signal handler. The response_promise is owned by each handler, and they
     * are responsible for freeing the outer ResponsePromise struct and unref'ing the credential and promise.
     */
    DexFuture *signal_handlers[G_N_ELEMENTS (public_key_credential_fibers)];
    for (int i = 0; i < G_N_ELEMENTS (public_key_credential_fibers); i++)
      {
        XdpCredentialResponsePromise *response_promise = g_new0(XdpCredentialResponsePromise, 1);
        response_promise->credential = g_object_ref (credential);
        response_promise->promise = dex_ref (promise);
        DexFiberFunc fiber = public_key_credential_fibers[i];
        signal_handlers[i] = dex_scheduler_spawn (NULL, 0, fiber, response_promise, NULL);
      }

    g_autoptr (GVariant) credential_response = dex_await_variant (dex_ref (DEX_FUTURE (promise)), &error);
    if (error != NULL)
      {
        g_warning ("Failed to get response for get credential: %s (%d)", error->message, error->code);
        xdp_request_dex_emit_response (request, XDG_DESKTOP_PORTAL_RESPONSE_OTHER, NULL);
      }
    else
      {
        xdp_request_dex_emit_response (request,
                                      XDG_DESKTOP_PORTAL_RESPONSE_SUCCESS,
                                      credential_response);
      }

    credentialsd_dbus_experimental_session_signal_monitor_cancel (credential->credsd_signal_monitor);
    dex_await (dex_future_allv (signal_handlers, G_N_ELEMENTS (public_key_credential_fibers)), &error);
    if (error != NULL)
      {
        g_warning ("Failed waiting for credentialsd signal handlers to complete: %s (%d)", error->message, error->code);
      }

    for (int i = 0; i < G_N_ELEMENTS (public_key_credential_fibers); i++)
      {
        DexFuture *signal_handler = DEX_FUTURE (signal_handlers[i]);
        dex_unref (signal_handler);
      }

    goto out;
  }

  out:
    g_clear_pointer (&credential->backend_session_id, g_free);
    g_clear_object (&credential->credsd_session);
    g_clear_object (&credential->credsd_signal_monitor);
    return G_DBUS_METHOD_INVOCATION_HANDLED;
}

static DexFuture *
discovery_requested_fiber (gpointer user_data)
{
  g_autoptr (GError) error = NULL;

  XdpCredential *credential = XDP_CREDENTIAL (user_data);

  while (dex_channel_can_receive(credential->impl_signal_monitor->discovery_requested_channel))
    {
      g_autoptr (XdpDbusExperimentalImplCredentialDiscoveryRequestedSignal) signal = NULL;
      signal = dex_await_boxed (xdp_dbus_experimental_impl_credential_signal_monitor_next_discovery_requested (
          credential->impl_signal_monitor
        ),
        &error
      );

      if (error)
        {
          // TODO: I think we can just exit since this means that the channel has closed and the portal has gone away.
          g_warning("Failed to receive DiscoveryRequested: %s (%d)", error->message, error->code);
          break;
        }
      g_debug("Received DiscoveryRequested from backend");

      CredentialsdDbusExperimentalSession *daemon_session = credential->credsd_session;
      // TODO: What am I supposed to do with this session handle?
      // TODO: Do we need start options?
      if (!dex_await (credentialsd_dbus_experimental_session_call_start_future (
         daemon_session), &error))
        {
          g_warning("Failed to send Start() %s (%d)", error->message, error->code);
        }
    }
    return dex_future_new_true();
}

static DexFuture *
client_pin_entered_fiber (gpointer user_data)
{
  g_autoptr (GError) error = NULL;

  XdpCredential *credential = XDP_CREDENTIAL (user_data);
  CredentialsdDbusExperimentalSession *daemon_session = credential->credsd_session;

  while (dex_channel_can_receive(credential->impl_signal_monitor->client_pin_entered_channel))
    {
      g_autoptr (XdpDbusExperimentalImplCredentialClientPinEnteredSignal) signal = NULL;
      signal = dex_await_boxed (xdp_dbus_experimental_impl_credential_signal_monitor_next_client_pin_entered (
          credential->impl_signal_monitor
        ),
        &error
      );

      if (error)
        {
          // TODO: I think we can just exit since this means that the channel has closed and the portal has gone away.
          g_warning("Failed to receive ClientPinEntered: %s (%d)", error->message, error->code);
          break;
        }

      g_debug ("Received ClientPinEntered from backend");
      // TODO: What am I supposed to do with this session handle?
      // TODO: gdbus/dex doesn't support receiving file descriptors over
      //       signals, need to convert this to a signal with a method to retrieve the
      //       data.
      if (!dex_await (credentialsd_dbus_experimental_session_call_enter_client_pin_future (
            daemon_session,
            signal->pin_fd,
            signal->options,
            NULL
          ),
          &error))
        {
          g_warning("Failed to call EnterClientPin() %s (%d)", error->message, error->code);
        }
    }

    return dex_future_new_true();
}

static DexFuture *
credential_selected_fiber (gpointer user_data)
{
  g_autoptr (GError) error = NULL;

  XdpCredential *credential = XDP_CREDENTIAL (user_data);
  CredentialsdDbusExperimentalSession *daemon_session = credential->credsd_session;

  while (dex_channel_can_receive(credential->impl_signal_monitor->credential_selected_channel))
    {
      g_autoptr (XdpDbusExperimentalImplCredentialCredentialSelectedSignal) signal = NULL;
      signal = dex_await_boxed (xdp_dbus_experimental_impl_credential_signal_monitor_next_credential_selected (
          credential->impl_signal_monitor
        ),
        &error
      );

      if (error)
        {
          // TODO: I think we can just exit since this means that the channel has closed and the portal has gone away.
          g_warning("Failed to receive CredentialSelected: %s (%d)", error->message, error->code);
          break;
        }
      g_debug ("Received CredentialSelected from backend");
      // TODO: What am I supposed to do with this session handle?
      if (!dex_await (credentialsd_dbus_experimental_session_call_select_credential_future (
          daemon_session,
          signal->id,
          signal->options
        ),
        &error))
        {
          g_warning("Failed to call SelectCredential() %s (%d)", error->message, error->code);
        }
    }
    return dex_future_new_true();
}

DexFuture *
init_credential (gpointer user_data)
{
  g_info ("Initializing Credential Portal");

  quark_credentialsd_error = g_quark_from_static_string("-credentialsd-error");

  XdpContext *context = XDP_CONTEXT (user_data);
  g_autoptr (XdpCredential) credential = NULL;
  g_autoptr (CredentialsdDbusExperimentalManager) manager = NULL;
  g_autoptr (XdpDbusExperimentalHandlerCredential) handler = NULL;
  g_autoptr (XdpDbusExperimentalImplCredential) impl = NULL;
  g_autoptr (GError) error = NULL;
  g_autoptr (XdpDbusExperimentalImplCredentialSignalMonitor) impl_signal_monitor = NULL;

  GDBusConnection *connection = xdp_context_get_connection (context);
  {
    XdpPortalConfig *config = xdp_context_get_config (context);
    XdpImplConfig *impl_config;

    impl_config =
        xdp_portal_config_find (config, CREDENTIAL_EXPERIMENTAL_DBUS_IMPL_IFACE);

    if (impl_config == NULL) {
      g_debug ("impl_config is NULL");
      return dex_future_new_true ();
    }

    g_debug ("found impl");

    impl = dex_await_object (xdp_dbus_experimental_impl_credential_proxy_new_future (
        connection,
        G_DBUS_PROXY_FLAGS_NONE,
        impl_config->dbus_name,
        DESKTOP_DBUS_PATH
      ),
      &error);

    if (!impl)
      {
        if (!g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
          g_warning ("Failed to create credential proxy: %s", error->message);
        return dex_future_new_false();
      }

    XdpDbusExperimentalImplCredentialSignals signals =
        XDP_DBUS_EXPERIMENTAL_IMPL_CREDENTIAL_SIGNAL_DISCOVERY_REQUESTED
      | XDP_DBUS_EXPERIMENTAL_IMPL_CREDENTIAL_SIGNAL_CLIENT_PIN_ENTERED
      | XDP_DBUS_EXPERIMENTAL_IMPL_CREDENTIAL_SIGNAL_CREDENTIAL_SELECTED;
    impl_signal_monitor = xdp_dbus_experimental_impl_credential_signal_monitor_new(impl, signals);
  }

  g_debug ("creating credentialsd manager proxy...");

  manager = dex_await_object (credentialsd_dbus_experimental_manager_proxy_new_future (
      connection,
      G_DBUS_PROXY_FLAGS_NONE,
      CREDENTIALSD_DBUS_NAME,
      "/xyz/iinuwa/credentialsd/Manager"
    ),
    &error);
  if (manager == NULL)
    {
      g_warning ("Failed to create credentialsd manager proxy: %s", error->message);
      return dex_future_new_false ();
    }
  g_debug ("created credentialsd manager proxy.");

  g_debug ("creating handler proxy...");

  handler = dex_await_object (xdp_dbus_experimental_handler_credential_proxy_new_future (
                                  connection,
                                  G_DBUS_PROXY_FLAGS_NONE,
                                  CREDENTIALSD_HANDLER_DBUS_NAME,
                                  DESKTOP_DBUS_PATH),
                              &error);

  if (!handler)
    {
      g_warning ("Failed to create credential proxy: %s", error->message);
      return dex_future_new_false ();
    }
  g_debug ("created handler proxy.");

  credential = xdp_credential_new (context,
                                   g_steal_pointer (&impl),
                                   g_steal_pointer (&impl_signal_monitor),
                                   g_steal_pointer (&manager),
                                   g_steal_pointer (&handler));

  g_autoptr (DexFuture) discovery_requested_future = dex_scheduler_spawn (NULL,
                                                                          0,
                                                                          discovery_requested_fiber,
                                                                          credential, NULL);
  g_autoptr (DexFuture) client_pin_entered_future = dex_scheduler_spawn (NULL,
                                                                          0,
                                                                          client_pin_entered_fiber,
                                                                          credential, NULL);
  g_autoptr (DexFuture) credential_selected_future = dex_scheduler_spawn (NULL,
                                                                          0,
                                                                          credential_selected_fiber,
                                                                          credential, NULL);

  xdp_context_take_and_export_portal (context,
                                      G_DBUS_INTERFACE_SKELETON (g_steal_pointer (&credential)),
                                      XDP_CONTEXT_EXPORT_FLAGS_RUN_IN_FIBER);

  return dex_future_new_true ();
}

#undef DEFINE_CREDENTIALSD_SIGNAL_CB
