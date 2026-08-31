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
#include "xdp-impl-experimental-dbus.h"
#include "xdp-portal-config.h"
#include "xdp-request-dex.h"
#include "xdp-utils.h"

#define DEFINE_CREDENTIALSD_SIGNAL_CB(signal_name, signal_str, snake_name, ...)                                        \
  static DexFuture *snake_name##_fiber (gpointer user_data)                                                            \
  {                                                                                                                    \
    g_autoptr (XdpCredentialRequestCtx) ctx = g_steal_pointer (&user_data);                                            \
                                                                                                                       \
    g_autoptr (CredentialsdDbusExperimentalSessionSignalMonitor) signal_monitor                                        \
      = g_object_ref (ctx->credsd_signal_monitor);                                                                     \
    if (signal_monitor->snake_name##_channel == NULL)                                                                  \
      {                                                                                                                \
        g_warning ("credential: " signal_str " not registered in signal monitor");                                     \
        return dex_future_new_false ();                                                                                \
      }                                                                                                                \
    g_autoptr (DexChannel) channel = dex_ref (signal_monitor->snake_name##_channel);                                   \
                                                                                                                       \
    while (dex_channel_can_receive (channel))                                                                          \
      {                                                                                                                \
        g_autoptr (GError) error = NULL;                                                                               \
        g_autoptr (CredentialsdDbusExperimentalSession##signal_name##Signal) signal = NULL;                            \
        signal = dex_await_boxed (                                                                                     \
          credentialsd_dbus_experimental_session_signal_monitor_next_##snake_name (signal_monitor), &error);           \
                                                                                                                       \
        if (error)                                                                                                     \
          {                                                                                                            \
            if (error->domain == dex_error_quark () && error->code == DEX_ERROR_CHANNEL_CLOSED)                        \
              {                                                                                                        \
                return dex_future_new_true ();                                                                         \
              }                                                                                                        \
            g_warning ("Failed to receive " signal_str ": %s (%d)", error->message, error->code);                      \
            return dex_future_new_false ();                                                                            \
          }                                                                                                            \
        g_debug ("Received " signal_str " from credentialsd");                                                         \
                                                                                                                       \
        XdpDbusExperimentalImplCredential *impl = ctx->credential->impl;                                               \
        if (!dex_await (xdp_dbus_experimental_impl_credential_call_notify_##snake_name##_future (                      \
                          impl, ctx->backend_session_id, __VA_ARGS__),                                                 \
                        &error))                                                                                       \
          {                                                                                                            \
            g_warning ("Failed to send " signal_str ": %s (%d)", error->message, error->code);                         \
          }                                                                                                            \
      }                                                                                                                \
    return dex_future_new_true ();                                                                                     \
  }

enum CredentialOperation
{
  CREDENTIAL_OPERATION_PUBLIC_KEY_CREATE = 0,
  CREDENTIAL_OPERATION_PUBLIC_KEY_GET = 1,
};

GQuark quark_credentialsd_error;

static gboolean handle_create_credential (XdpDbusExperimentalCredential *object, GDBusMethodInvocation *invocation,
                                          const gchar *arg_parent_window, const gchar *arg_origin,
                                          const gchar *arg_type, GVariant *arg_options);

static gboolean handle_get_credential (XdpDbusExperimentalCredential *object, GDBusMethodInvocation *invocation,
                                       const gchar *arg_parent_window, const gchar *arg_origin, GVariant *arg_options);

struct _XdpCredential
{
  XdpDbusExperimentalCredentialSkeleton parent_instance;

  /**
   * Reference to the main context, not owned by this struct.
   */
  XdpContext *context;

  /**
   * A D-Bus proxy for the Credential Portal backend interface.
   * Valid for the lifetime of this portal.
   */
  XdpDbusExperimentalImplCredential *impl;

  /**
   * A D-Bus proxy for the credentialsd Manager interface, which is used to
   * start new credentialsd sessions.
   * Valid for the lifetime of this portal.
   */
  CredentialsdDbusExperimentalManager *manager;

  gboolean request_is_active;
};

G_DECLARE_FINAL_TYPE (XdpCredential, xdp_credential, XDP, CREDENTIAL, XdpDbusExperimentalCredentialSkeleton)

static void xdp_credential_iface_init (XdpDbusExperimentalCredentialIface *iface);

G_DEFINE_FINAL_TYPE_WITH_CODE (XdpCredential, xdp_credential, XDP_DBUS_EXPERIMENTAL_TYPE_CREDENTIAL_SKELETON,
                               G_IMPLEMENT_INTERFACE (XDP_DBUS_EXPERIMENTAL_TYPE_CREDENTIAL,
                                                      xdp_credential_iface_init));

static void
xdp_credential_iface_init (XdpDbusExperimentalCredentialIface *iface)
{
  iface->handle_create_credential = handle_create_credential;
  iface->handle_get_credential = handle_get_credential;
}

static void
xdp_credential_dispose (GObject *object)
{
  XdpCredential *credential = XDP_CREDENTIAL (object);

  // credential->context is not owned by this object, so not clearing here.

  g_clear_object (&credential->impl);
  g_clear_object (&credential->manager);

  G_OBJECT_CLASS (xdp_credential_parent_class)->dispose (object);
}

static void
xdp_credential_init (XdpCredential *credential)
{
}

static void
xdp_credential_class_init (XdpCredentialClass *klass)
{
  GObjectClass *object_class = G_OBJECT_CLASS (klass);

  object_class->dispose = xdp_credential_dispose;
}

/**
 * xdp_credential_new:
 * @context: (transfer none): Portal context.
 * @impl: (transfer full): D-Bus proxy for Credential portal backend interface.
 * @manager: (transfer full): D-Bus proxy for credentialsd Manager interface.
 */
static XdpCredential *
xdp_credential_new (XdpContext *context, XdpDbusExperimentalImplCredential *impl,
                    CredentialsdDbusExperimentalManager *manager)
{
  XdpCredential *credential;

  credential = g_object_new (xdp_credential_get_type (), NULL);
  credential->context = context;
  credential->impl = impl;
  credential->manager = manager;

  credential->request_is_active = FALSE;

  xdp_dbus_experimental_credential_set_conditional_create (XDP_DBUS_EXPERIMENTAL_CREDENTIAL (credential), FALSE);
  xdp_dbus_experimental_credential_set_conditional_get (XDP_DBUS_EXPERIMENTAL_CREDENTIAL (credential), FALSE);
  xdp_dbus_experimental_credential_set_hybrid_transport (XDP_DBUS_EXPERIMENTAL_CREDENTIAL (credential), TRUE);
  xdp_dbus_experimental_credential_set_passkey_platform_authenticator (XDP_DBUS_EXPERIMENTAL_CREDENTIAL (credential),
                                                                       TRUE);
  xdp_dbus_experimental_credential_set_user_verifying_platform_authenticator (
    XDP_DBUS_EXPERIMENTAL_CREDENTIAL (credential), FALSE);
  xdp_dbus_experimental_credential_set_related_origins (XDP_DBUS_EXPERIMENTAL_CREDENTIAL (credential), TRUE);
  xdp_dbus_experimental_credential_set_signal_all_accepted_credentials (XDP_DBUS_EXPERIMENTAL_CREDENTIAL (credential),
                                                                        FALSE);
  xdp_dbus_experimental_credential_set_signal_current_user_details (XDP_DBUS_EXPERIMENTAL_CREDENTIAL (credential),
                                                                    FALSE);
  xdp_dbus_experimental_credential_set_signal_unknown_credential (XDP_DBUS_EXPERIMENTAL_CREDENTIAL (credential), FALSE);

  xdp_dbus_experimental_credential_set_version (XDP_DBUS_EXPERIMENTAL_CREDENTIAL (credential), 1);

  return credential;
}

/** Data valid for the lifetime of a single request. */
typedef struct _XdpCredentialRequestCtx
{
  /** Reference to the credential portal object. */
  XdpCredential *credential;

  /**
   * The session handle for a Credential Portal backend Session object.
   */
  gchar *backend_session_id;

  /**
   * A D-Bus proxy for a credentialsd Session object.
   */
  CredentialsdDbusExperimentalSession *credsd_session;

  /** Promise for the response. */
  DexPromise *promise;

  /**
   * A signal monitor to receive signals from the backend proxy for the
   * Credential Portal backend interface.
   * NULL in credentialsd signal fibers.
   */
  XdpDbusExperimentalImplCredentialSignalMonitor *impl_signal_monitor;

  /**
   * A Dex signal monitor for a credentialsd Session object.
   * NULL in backend signal fibers.
   */
  CredentialsdDbusExperimentalSessionSignalMonitor *credsd_signal_monitor;
} XdpCredentialRequestCtx;

/**
 * xdp_credential_request_ctx_init_for_backend:
 * @credential: (transfer full): Reference to the portal context.
 * @backend_session_id: (transfer full): Session ID for this request.
 * @credsd_session: (transfer full): D-Bus proxy for the related credentialsd Session object.
 * @promise: (transfer full): Promise to return to the caller.
 * @impl_signal_monitor: (transfer full): Signal monitor with all backend signals subscribed.
 *
 * Initialize request context for use in a Credential portal signal backend handler.
 */
static void
xdp_credential_request_ctx_init_for_backend (XdpCredentialRequestCtx *self, XdpCredential *credential,
                                             gchar *backend_session_id,
                                             CredentialsdDbusExperimentalSession *credsd_session, DexPromise *promise,
                                             XdpDbusExperimentalImplCredentialSignalMonitor *impl_signal_monitor)
{
  self->credential = credential;
  self->backend_session_id = backend_session_id;
  self->credsd_session = credsd_session;
  self->promise = promise;
  self->impl_signal_monitor = impl_signal_monitor;
  self->credsd_signal_monitor = NULL;
}

/**
 * xdp_credential_request_ctx_init_for_credentialsd:
 * @credential: (transfer full): Reference to the portal context.
 * @backend_session_id: (transfer full): Session ID for this request.
 * @credsd_session: (transfer full): D-Bus proxy for the related credentialsd Session object.
 * @promise: (transfer full): Promise to return to the caller.
 * @credsd_signal_monitor: (transfer full): Signal monitor with all credentialsd Session signals subscribed.
 *
 * Initialize request context for use in a credentialsd session signal handler.
 */
static void
xdp_credential_request_ctx_init_for_credentialsd (
  XdpCredentialRequestCtx *self, XdpCredential *credential, gchar *backend_session_id,
  CredentialsdDbusExperimentalSession *credsd_session, DexPromise *promise,
  CredentialsdDbusExperimentalSessionSignalMonitor *credsd_signal_monitor)
{
  self->credential = credential;
  self->backend_session_id = backend_session_id;
  self->credsd_session = credsd_session;
  self->promise = promise;
  self->impl_signal_monitor = NULL;
  self->credsd_signal_monitor = credsd_signal_monitor;
}

static void
xdp_credential_request_ctx_free (XdpCredentialRequestCtx *self)
{
  g_clear_object (&self->credential);
  g_clear_pointer (&self->backend_session_id, g_free);
  g_clear_pointer (&self->promise, dex_unref);
  g_clear_object (&self->impl_signal_monitor);
  g_clear_object (&self->credsd_session);
  g_clear_object (&self->credsd_signal_monitor);
  g_free (self);
}

G_DEFINE_AUTOPTR_CLEANUP_FUNC (XdpCredentialRequestCtx, xdp_credential_request_ctx_free)

typedef struct _XdpCredentialRequestGuard
{
  XdpCredential *credential;
} XdpCredentialRequestGuard;

static void
xdp_credential_request_guard_cleanup (XdpCredentialRequestGuard *self)
{
  g_atomic_int_set (&self->credential->request_is_active, FALSE);
  g_free (self);
}

G_DEFINE_AUTOPTR_CLEANUP_FUNC (XdpCredentialRequestGuard, xdp_credential_request_guard_cleanup)

/**
 * xdp_credential_guard_request:
 * @credential: The Credential portal context.
 * @guard: A pointer to memory to initialize the guard object.
 */
static gboolean
xdp_credential_guard_request (XdpCredential *credential, XdpCredentialRequestGuard **guard, GError **error)
{
  if (!g_atomic_int_compare_and_exchange (&credential->request_is_active, FALSE, TRUE))
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_BUSY, "Request is already in progress");
      return FALSE;
    }
  *guard = g_new0 (XdpCredentialRequestGuard, 1);
  (*guard)->credential = credential;
  return TRUE;
}

const gchar *CREDENTIALSD_DBUS_NAME = "xyz.iinuwa.credentialsd.Credentials";

DEFINE_CREDENTIALSD_SIGNAL_CB (NeedsPin, "NeedsPin", needs_pin, signal->attempts_left, signal->_options)

DEFINE_CREDENTIALSD_SIGNAL_CB (NeedsUserVerification, "NeedsUserVerification", needs_user_verification,
                               signal->attempts_left, signal->_options)

DEFINE_CREDENTIALSD_SIGNAL_CB (NeedsUserPresence, "NeedsUserPresence", needs_user_presence, signal->_options)

DEFINE_CREDENTIALSD_SIGNAL_CB (SelectingCredential, "SelectingCredential", selecting_credential, signal->credentials,
                               signal->_options)

static DexFuture *
hybrid_started_fiber (gpointer user_data)
{
  g_autoptr (XdpCredentialRequestCtx) ctx = g_steal_pointer (&user_data);

  g_autoptr (CredentialsdDbusExperimentalSessionSignalMonitor) signal_monitor
    = g_object_ref (ctx->credsd_signal_monitor);
  if (signal_monitor->hybrid_started_channel == NULL)
    {
      g_warning ("credential: HybridStarted not registered in signal monitor");
      return dex_future_new_false ();
    }
  g_autoptr (DexChannel) channel = dex_ref (signal_monitor->hybrid_started_channel);
  while (dex_channel_can_receive (channel))
    {
      g_autoptr (GError) error = NULL;
      g_autoptr (CredentialsdDbusExperimentalSessionHybridStartedSignal) signal = NULL;
      signal = dex_await_boxed (
        credentialsd_dbus_experimental_session_signal_monitor_next_hybrid_started (signal_monitor), &error);

      if (error)
        {
          if (error->domain == dex_error_quark () && error->code == DEX_ERROR_CHANNEL_CLOSED)
            {
              return dex_future_new_true ();
            }

          g_warning ("Failed to receive HybridStarted: %s (%d)", error->message, error->code);
          return dex_future_new_false ();
        }
      g_debug ("Received HybridStarted from credentialsd");

      g_autoptr (GUnixFDList) fd_list = g_unix_fd_list_new ();

      g_autoptr (CredentialsdDbusExperimentalSessionGetHybridInvocationDataResult) invocation_data_result = NULL;
      invocation_data_result = dex_await_boxed (
        credentialsd_dbus_experimental_session_call_get_hybrid_invocation_data_future (ctx->credsd_session, fd_list),
        &error);
      if (!invocation_data_result)
        {
          // TODO: shutdown
          g_warning ("Could not retrieve hybrid invocation data fd: %s (%d)", error->message, error->code);
          return dex_future_new_false ();
        }

      XdpDbusExperimentalImplCredential *impl = ctx->credential->impl;
      gboolean notified = dex_await (xdp_dbus_experimental_impl_credential_call_notify_hybrid_started_future (
                                       impl, ctx->backend_session_id, invocation_data_result->invocation_data,
                                       signal->_options, invocation_data_result->fd_list),
                                     &error);
      if (!notified)
        g_warning ("Failed to send HybridStarted: %s (%d)", error->message, error->code);
    }
  return dex_future_new_true ();
}

DEFINE_CREDENTIALSD_SIGNAL_CB (HybridConnecting, "HybridConnecting", hybrid_connecting, signal->_options)

DEFINE_CREDENTIALSD_SIGNAL_CB (HybridConnected, "HybridConnected", hybrid_connected, signal->_options)

DEFINE_CREDENTIALSD_SIGNAL_CB (NfcConnected, "NfcConnected", nfc_connected, signal->_options)

DEFINE_CREDENTIALSD_SIGNAL_CB (UsbConnected, "UsbConnected", usb_connected, signal->_options)

static DexFuture *
ceremony_completed_fiber (gpointer user_data)
{
  g_autoptr (XdpCredentialRequestCtx) ctx = g_steal_pointer (&user_data);

  g_autoptr (CredentialsdDbusExperimentalSessionSignalMonitor) signal_monitor
    = g_object_ref (ctx->credsd_signal_monitor);
  if (signal_monitor->ceremony_completed_channel == NULL)
    {
      g_warning ("credential: CeremonyCompleted not registered in signal monitor");
      return dex_future_new_false ();
    }
  g_autoptr (DexChannel) channel = dex_ref (signal_monitor->ceremony_completed_channel);

  while (dex_channel_can_receive (channel))
    {
      g_autoptr (GError) error = NULL;
      g_autoptr (CredentialsdDbusExperimentalSessionCeremonyCompletedSignal) signal = NULL;
      signal = dex_await_boxed (
        credentialsd_dbus_experimental_session_signal_monitor_next_ceremony_completed (signal_monitor), &error);

      if (error != NULL)
        {
          if (error->domain == dex_error_quark () && error->code == DEX_ERROR_CHANNEL_CLOSED)
            {
              return dex_future_new_true ();
            }

          g_warning ("Failed to receive CeremonyCompleted: %s (%d)", error->message, error->code);
          dex_promise_reject (ctx->promise, g_steal_pointer (&error));
          return dex_future_new_false ();
        }

      g_info ("Received CeremonyCompleted");
      XdpDbusExperimentalImplCredential *impl = ctx->credential->impl;
      gboolean notified = dex_await (
        xdp_dbus_experimental_impl_credential_call_notify_ceremony_completed_future (impl, ctx->backend_session_id),
        &error);
      if (!notified)
        g_warning ("Failed to send CeremonyCompleted %s (%d)", error->message, error->code);
      dex_promise_resolve_variant (ctx->promise, g_variant_ref (signal->response));
    }
  return dex_future_new_true ();
}

static DexFuture *
error_occurred_fiber (gpointer user_data)
{
  g_autoptr (XdpCredentialRequestCtx) ctx = g_steal_pointer (&user_data);

  g_autoptr (CredentialsdDbusExperimentalSessionSignalMonitor) signal_monitor
    = g_object_ref (ctx->credsd_signal_monitor);
  if (signal_monitor->error_occurred_channel == NULL)
    {
      g_warning ("credential: ErrorOccurred not registered in signal monitor");
      return dex_future_new_false ();
    }
  g_autoptr (DexChannel) channel = dex_ref (signal_monitor->error_occurred_channel);

  while (dex_channel_can_receive (channel))
    {
      g_autoptr (GError) error = NULL;
      g_autoptr (CredentialsdDbusExperimentalSessionErrorOccurredSignal) signal = NULL;
      signal = dex_await_boxed (
        credentialsd_dbus_experimental_session_signal_monitor_next_error_occurred (signal_monitor), &error);

      if (error != NULL)
        {
          if (error->domain == dex_error_quark () && error->code == DEX_ERROR_CHANNEL_CLOSED)
            {
              return dex_future_new_true ();
            }

          g_warning ("Failed to receive ErrorOccurred: %s (%d)", error->message, error->code);
          dex_promise_reject (ctx->promise, g_steal_pointer (&error));
          return dex_future_new_false ();
        }

      g_debug ("Received ErrorOccurred");
      XdpDbusExperimentalImplCredential *impl = ctx->credential->impl;
      gboolean notified = dex_await (xdp_dbus_experimental_impl_credential_call_notify_error_occurred_future (
                                       impl, ctx->backend_session_id, signal->error),
                                     &error);
      if (!notified)
        g_warning ("Failed to send ErrorOccurred %s (%d)", error->message, error->code);
      g_set_error (&error, quark_credentialsd_error, signal->error, "credentialsd session returned an error");
      dex_promise_reject (ctx->promise, g_steal_pointer (&error));
    }

  return dex_future_new_true ();
}

/**
 * Fiber functions to be used during a create or get credential request.
 */
static DexFiberFunc public_key_credential_fibers[]
  = { needs_pin_fiber,          needs_user_verification_fiber, needs_user_presence_fiber,
      hybrid_started_fiber,     hybrid_connecting_fiber,       hybrid_connected_fiber,
      nfc_connected_fiber,      usb_connected_fiber,           selecting_credential_fiber,
      ceremony_completed_fiber, error_occurred_fiber };

static DexFuture *
discovery_requested_fiber (gpointer user_data)
{
  g_autoptr (XdpCredentialRequestCtx) ctx = g_steal_pointer (&user_data);

  if (ctx->impl_signal_monitor == NULL)
    {
      g_warning ("credential: backend signal monitor is NULL, cannot answer any requests");
      return dex_future_new_false ();
    }

  if (ctx->impl_signal_monitor->discovery_requested_channel == NULL)
    {
      g_warning ("credential: DiscoveryRequested channel was not subscribed "
                 "in signal monitor");
      return dex_future_new_false ();
    }
  g_autoptr (DexChannel) channel = dex_ref (ctx->impl_signal_monitor->discovery_requested_channel);

  while (dex_channel_can_receive (channel))
    {
      g_autoptr (GError) error = NULL;
      g_autoptr (XdpDbusExperimentalImplCredentialDiscoveryRequestedSignal) signal = NULL;
      signal = dex_await_boxed (
        xdp_dbus_experimental_impl_credential_signal_monitor_next_discovery_requested (ctx->impl_signal_monitor),
        &error);

      if (error)
        {
          if (error->domain == dex_error_quark () && error->code == DEX_ERROR_CHANNEL_CLOSED)
            {
              return dex_future_new_true ();
            }

          g_warning ("Failed to receive DiscoveryRequested: %s (%d)", error->message, error->code);
          break;
        }
      g_debug ("Received DiscoveryRequested from backend");

      if (g_strcmp0 (signal->session_handle, ctx->backend_session_id) != 0)
        {
          // Signal is for another request, ignoring.
          continue;
        }
      g_autoptr (CredentialsdDbusExperimentalSession) daemon_session = g_object_ref (ctx->credsd_session);
      // TODO: Do we need start options?
      if (!dex_await (credentialsd_dbus_experimental_session_call_start_future (daemon_session), &error))
        {
          g_warning ("Failed to send Start() %s (%d)", error->message, error->code);
        }
    }
  return dex_future_new_true ();
}

static DexFuture *
client_pin_entered_fiber (gpointer user_data)
{
  g_autoptr (XdpCredentialRequestCtx) ctx = g_steal_pointer (&user_data);

  if (ctx->impl_signal_monitor == NULL)
    {
      g_warning ("credential: backend signal monitor is NULL, cannot answer any requests");
      return dex_future_new_false ();
    }

  if (ctx->impl_signal_monitor->client_pin_entered_channel == NULL)
    {
      g_warning ("credential: ClientPinEntered channel was not subscribed in "
                 "signal monitor");
      return dex_future_new_false ();
    }
  g_autoptr (DexChannel) channel = dex_ref (ctx->impl_signal_monitor->client_pin_entered_channel);

  while (dex_channel_can_receive (channel))
    {
      g_autoptr (GError) error = NULL;
      g_autoptr (XdpDbusExperimentalImplCredentialClientPinEnteredSignal) signal = NULL;
      signal = dex_await_boxed (
        xdp_dbus_experimental_impl_credential_signal_monitor_next_client_pin_entered (ctx->impl_signal_monitor),
        &error);

      if (error)
        {
          if (error->domain == dex_error_quark () && error->code == DEX_ERROR_CHANNEL_CLOSED)
            {
              return dex_future_new_true ();
            }

          g_warning ("Failed to receive ClientPinEntered: %s (%d)", error->message, error->code);
          break;
        }

      g_debug ("Received ClientPinEntered from backend");
      if (g_strcmp0 (signal->session_handle, ctx->backend_session_id) != 0)
        {
          // Signal is for another request, ignoring.
          continue;
        }
      g_autoptr (CredentialsdDbusExperimentalSession) daemon_session = g_object_ref (ctx->credsd_session);
      // TODO: gdbus/dex doesn't support receiving file descriptors over
      //       signals, need to convert this to a signal with a method to
      //       retrieve the data.
      if (!dex_await (credentialsd_dbus_experimental_session_call_enter_client_pin_future (
                        daemon_session, signal->pin_fd, signal->options, NULL),
                      &error))
        {
          g_warning ("Failed to call EnterClientPin() %s (%d)", error->message, error->code);
        }
    }

  return dex_future_new_true ();
}

static DexFuture *
credential_selected_fiber (gpointer user_data)
{
  g_autoptr (XdpCredentialRequestCtx) ctx = g_steal_pointer (&user_data);

  if (ctx->impl_signal_monitor == NULL)
    {
      g_warning ("credential: backend signal monitor is NULL, cannot answer any requests");
      return dex_future_new_false ();
    }

  if (ctx->impl_signal_monitor->credential_selected_channel == NULL)
    {
      g_warning ("credential: CredentialSelected channel was not subscribed in signal monitor");
      return dex_future_new_false ();
    }
  g_autoptr (DexChannel) channel = dex_ref (ctx->impl_signal_monitor->credential_selected_channel);

  while (dex_channel_can_receive (channel))
    {
      g_autoptr (GError) error = NULL;
      g_autoptr (XdpDbusExperimentalImplCredentialCredentialSelectedSignal) signal = NULL;
      signal = dex_await_boxed (
        xdp_dbus_experimental_impl_credential_signal_monitor_next_credential_selected (ctx->impl_signal_monitor),
        &error);

      if (error)
        {
          if (error->domain == dex_error_quark () && error->code == DEX_ERROR_CHANNEL_CLOSED)
            {
              return dex_future_new_true ();
            }

          g_warning ("Failed to receive CredentialSelected: %s (%d)", error->message, error->code);
          break;
        }
      g_debug ("Received CredentialSelected from backend");
      if (g_strcmp0 (signal->session_handle, ctx->backend_session_id) != 0)
        {
          // Signal is for another request, ignoring.
          continue;
        }
      if (!dex_await (credentialsd_dbus_experimental_session_call_select_credential_future (
                        ctx->credsd_session, signal->id, signal->options),
                      &error))
        {
          g_warning ("Failed to call SelectCredential() %s (%d)", error->message, error->code);
        }
    }
  return dex_future_new_true ();
}

static DexFiberFunc public_key_credential_impl_fibers[] = {
  discovery_requested_fiber,
  client_pin_entered_fiber,
  credential_selected_fiber,
};

/**
 * Function to perform credential ceremony for either get or create.
 */
static gboolean
handle_credential_request (XdpCredential *credential, XdpRequestDex *request, enum CredentialOperation operation,
                           const gchar *arg_parent_window, const gchar *arg_origin, gchar *top_origin, void *data,
                           GVariantDict *backend_options_dict, const gchar *app_id)
{
  g_autoptr (CredentialsdDbusExperimentalSession) credsd_session = NULL;
  g_autoptr (CredentialsdDbusExperimentalSessionSignalMonitor) credsd_signal_monitor = NULL;
  g_autoptr (XdpDbusExperimentalImplCredentialSignalMonitor) impl_signal_monitor = NULL;
  g_autofree gchar *daemon_session_handle = NULL;
  g_autoptr (GVariant) credential_response = NULL;
  g_autoptr (DexPromise) promise = NULL;
  g_autoptr (GVariant) backend_options = NULL;
  g_autoptr (GError) error = NULL;
  DexFuture *impl_signal_handlers[G_N_ELEMENTS (public_key_credential_impl_fibers)] = { NULL };
  DexFuture *signal_handlers[G_N_ELEMENTS (public_key_credential_fibers)] = { NULL };
  gboolean ret = FALSE;

  {
    GDBusConnection *connection = xdp_context_get_connection (credential->context);
    if (operation == CREDENTIAL_OPERATION_PUBLIC_KEY_GET)
      {
        GVariant *frontend_options = (GVariant *)data;
        g_autoptr (CredentialsdDbusExperimentalManagerGetCredentialResult) daemon_session_result = NULL;
        daemon_session_result = dex_await_boxed (credentialsd_dbus_experimental_manager_call_get_credential_future (
                                                   credential->manager, arg_origin, top_origin, frontend_options),
                                                 &error);
        if (daemon_session_result == NULL)
          {
            g_warning ("Failed to create proxy for credentialsd session: %s (%d)", error->message, error->code);
            xdp_request_dex_emit_response (request, XDG_DESKTOP_PORTAL_RESPONSE_OTHER, NULL);
            return FALSE;
          }
        daemon_session_handle = g_strdup (daemon_session_result->session_handle);
      }
    else if (operation == CREDENTIAL_OPERATION_PUBLIC_KEY_CREATE)
      {
        g_autoptr (CredentialsdDbusExperimentalManagerCreatePublicKeyCredentialResult) daemon_session_result = NULL;
        gchar *request_json = (gchar *)data;
        daemon_session_result
          = dex_await_boxed (credentialsd_dbus_experimental_manager_call_create_public_key_credential_future (
                               credential->manager, request_json, arg_origin, top_origin),
                             &error);
        if (daemon_session_result == NULL)
          {
            g_warning ("Failed to create proxy for credentialsd session: %s (%d)", error->message, error->code);
            xdp_request_dex_emit_response (request, XDG_DESKTOP_PORTAL_RESPONSE_OTHER, NULL);
            return FALSE;
          }
        daemon_session_handle = g_strdup (daemon_session_result->session_handle);
      }
    else
      {
        g_assert_not_reached ();
      }
    credsd_session
      = dex_await_object (credentialsd_dbus_experimental_session_proxy_new_future (
                            connection, G_DBUS_PROXY_FLAGS_NONE, CREDENTIALSD_DBUS_NAME, daemon_session_handle),
                          &error);
    if (credsd_session == NULL)
      {
        g_warning ("Failed to create proxy for credentialsd session: %s (%d)", error->message, error->code);
        xdp_request_dex_emit_response (request, XDG_DESKTOP_PORTAL_RESPONSE_OTHER, NULL);
        return FALSE;
      }
  }

  GVariant *devices = credentialsd_dbus_experimental_session_get_devices (credsd_session);

  g_variant_dict_insert (backend_options_dict, "rp_id", "s",
                         credentialsd_dbus_experimental_session_get_rp_id (credsd_session));
  backend_options = g_variant_ref_sink (g_variant_dict_end (g_steal_pointer (&backend_options_dict)));

  // TODO: Remove this from backend.
  int pid = 0;

  promise = dex_promise_new ();

  XdpDbusExperimentalImplCredentialSignals impl_signals
    = XDP_DBUS_EXPERIMENTAL_IMPL_CREDENTIAL_SIGNAL_DISCOVERY_REQUESTED
      | XDP_DBUS_EXPERIMENTAL_IMPL_CREDENTIAL_SIGNAL_CLIENT_PIN_ENTERED
      | XDP_DBUS_EXPERIMENTAL_IMPL_CREDENTIAL_SIGNAL_CREDENTIAL_SELECTED;
  impl_signal_monitor = xdp_dbus_experimental_impl_credential_signal_monitor_new (credential->impl, impl_signals);

  for (int i = 0; i < G_N_ELEMENTS (public_key_credential_impl_fibers); i++)
    {
      DexFiberFunc fiber = public_key_credential_impl_fibers[i];
      XdpCredentialRequestCtx *ctx = g_new0 (XdpCredentialRequestCtx, 1);
      xdp_credential_request_ctx_init_for_backend (ctx, g_object_ref (credential), g_strdup (daemon_session_handle),
                                                   g_object_ref (credsd_session), dex_ref (promise),
                                                   g_object_ref (impl_signal_monitor));
      impl_signal_handlers[i] = dex_scheduler_spawn (NULL, 0, fiber, ctx, NULL);
    }

  CredentialsdDbusExperimentalSessionSignals signals
    = CREDENTIALSD_DBUS_EXPERIMENTAL_SESSION_SIGNAL_NEEDS_PIN
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
  credsd_signal_monitor = credentialsd_dbus_experimental_session_signal_monitor_new (credsd_session, signals);

  /**
   * we pass a reference to the Credential object and the request data to each
   * signal handler. The ctx is owned by each handler, and they
   * are responsible for freeing the XdpCredentialRequestCtx struct.
   */
  for (int i = 0; i < G_N_ELEMENTS (public_key_credential_fibers); i++)
    {
      XdpCredentialRequestCtx *ctx = g_new0 (XdpCredentialRequestCtx, 1);
      xdp_credential_request_ctx_init_for_credentialsd (ctx, g_object_ref (credential),
                                                        g_strdup (daemon_session_handle), g_object_ref (credsd_session),
                                                        dex_ref (promise), g_object_ref (credsd_signal_monitor));
      DexFiberFunc fiber = public_key_credential_fibers[i];
      signal_handlers[i] = dex_scheduler_spawn (NULL, 0, fiber, ctx, NULL);
    }

  if (!dex_await (xdp_dbus_experimental_impl_credential_call_create_session_future (
                    credential->impl, daemon_session_handle, arg_parent_window, arg_origin, operation, devices, app_id,
                    pid, backend_options),
                  &error))
    {
      g_warning ("Failed to create backend session: %s (%d)", error->message, error->code);
      xdp_request_dex_emit_response (request, XDG_DESKTOP_PORTAL_RESPONSE_OTHER, NULL);
      goto out;
    }

  credential_response = dex_await_variant (dex_ref (DEX_FUTURE (promise)), &error);
  if (error != NULL)
    {
      g_warning ("Failed to get credential response: %s (%d)", error->message, error->code);
      xdp_request_dex_emit_response (request, XDG_DESKTOP_PORTAL_RESPONSE_OTHER, NULL);
      goto out;
    }
  else
    {
      xdp_request_dex_emit_response (request, XDG_DESKTOP_PORTAL_RESPONSE_SUCCESS, credential_response);
      goto out;
    }

out:
  ret = (error == NULL);
  g_clear_error (&error);

  // Clean up credentialsd Session signal handlers
  if (credsd_signal_monitor != NULL)
    {
      credentialsd_dbus_experimental_session_signal_monitor_cancel (credsd_signal_monitor);
      dex_await (dex_future_allv (signal_handlers, G_N_ELEMENTS (public_key_credential_fibers)), &error);
      if (error != NULL)
        {
          g_warning ("Failed waiting for credentialsd signal handlers to complete: %s (%d)", error->message,
                     error->code);
          g_clear_error (&error);
        }

      for (int i = 0; i < G_N_ELEMENTS (public_key_credential_fibers); i++)
        {
          if (signal_handlers[i] != NULL)
            {
              DexFuture *signal_handler = DEX_FUTURE (signal_handlers[i]);
              dex_unref (signal_handler);
            }
        }
    }

  // Clean up impl backend Session signal handlers
  if (impl_signal_monitor != NULL)
    {
      xdp_dbus_experimental_impl_credential_signal_monitor_cancel (impl_signal_monitor);
      dex_await (dex_future_allv (impl_signal_handlers, G_N_ELEMENTS (public_key_credential_impl_fibers)), &error);
      if (error != NULL)
        {
          g_warning ("Failed waiting for impl signal handlers to complete: %s (%d)", error->message, error->code);
          g_clear_error (&error);
        }

      for (int i = 0; i < G_N_ELEMENTS (public_key_credential_impl_fibers); i++)
        {
          if (impl_signal_handlers[i] != NULL)
            {
              DexFuture *signal_handler = DEX_FUTURE (impl_signal_handlers[i]);
              dex_unref (signal_handler);
            }
        }
    }

  return ret;
}

static XdpOptionKey create_credential_options[] = {
  { "handle_token", G_VARIANT_TYPE_STRING, NULL }, { "origin", G_VARIANT_TYPE_STRING, NULL },
  { "top_origin", G_VARIANT_TYPE_STRING, NULL },   { "type", G_VARIANT_TYPE_STRING, NULL },
  { "public_key", G_VARIANT_TYPE_STRING, NULL },
};

/**
 * create_credential_validate_options:
 * @arg_options: (transfer none): options passed to the frontend.
 * @arg_type: (transfer none): options passed to the frontend.
 * @frontend_options: (transfer none): options passed to the frontend.
 * @backend_options: (transfer none): options passed to the frontend.
 * @request_json: (transfer none): pointer to string to be filled with request
 * JSON.
 * @top_origin: (transfer none): pointer to string to top_origin field. May be
 * NULL.
 * @error: (transfer none): pointer to an error pointer that will be populated
 * on error.
 * Returns: TRUE when options are validated successfully.
 */
static gboolean
create_credential_validate_options (GVariant *arg_options, const gchar *arg_type, GVariant **frontend_options,
                                    GVariantDict **backend_options, gchar **request_json, gchar **top_origin,
                                    GError **error)
{
  g_auto (GVariantBuilder) options = G_VARIANT_BUILDER_INIT (G_VARIANT_TYPE_VARDICT);
  g_autofree gchar *json = NULL;
  g_autofree gchar *top_origin_tmp = NULL;
  g_autoptr (GVariantDict) backend_options_dict = NULL;

  if (!xdp_filter_options (arg_options, &options, create_credential_options, G_N_ELEMENTS (create_credential_options),
                           NULL, error))
    {
      return FALSE;
    }

  if (g_strcmp0 (arg_type, "publicKey") != 0)
    {
      g_set_error (error, XDG_DESKTOP_PORTAL_ERROR, XDG_DESKTOP_PORTAL_ERROR_INVALID_ARGUMENT,
                   "Invalid credential type: `%s`. Supported types [`publicKey`]", arg_type);
      return FALSE;
    }

  if (!g_variant_lookup (arg_options, "public_key", "s", &json))
    {
      g_set_error (error, XDG_DESKTOP_PORTAL_ERROR, XDG_DESKTOP_PORTAL_ERROR_INVALID_ARGUMENT,
                   "`public_key` option is required when `publicKey` "
                   "credential type is requested");
      return FALSE;
    };

  {
    backend_options_dict = g_variant_dict_new (NULL);

    g_autofree gchar *activation_token = NULL;
    // TODO: I don't think this else statement is necessary; check bug in
    // credentialsd
    if (g_variant_lookup (arg_options, "activation_token", "s", &activation_token))
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

static gboolean
handle_create_credential (XdpDbusExperimentalCredential *object, GDBusMethodInvocation *invocation,
                          const gchar *arg_parent_window, const gchar *arg_origin, const gchar *arg_type,
                          GVariant *arg_options)
{
  XdpCredential *credential = XDP_CREDENTIAL (object);
  g_autoptr (XdpRequestDex) request = NULL;
  g_autoptr (GError) error = NULL;
  g_autoptr (GVariant) frontend_options = NULL;
  g_autoptr (GVariantDict) backend_options_dict = NULL;
  g_autofree gchar *request_json = NULL;
  g_autofree gchar *top_origin = NULL;
  g_autofree gchar *daemon_session_handle = NULL;
  g_autoptr (XdpCredentialRequestGuard) guard = NULL;

  if (!xdp_credential_guard_request (credential, &guard, &error))
    {
      g_dbus_method_invocation_return_gerror (g_steal_pointer (&invocation), error);
      return G_DBUS_METHOD_INVOCATION_HANDLED;
    };

  XdpAppInfo *app_info = xdp_invocation_get_app_info (invocation);
  const gchar *app_id = xdp_app_info_get_id (app_info);

  gboolean is_validated = create_credential_validate_options (
    arg_options, arg_type, &frontend_options, &backend_options_dict, &request_json, &top_origin, &error);

  if (!is_validated)
    {
      g_dbus_method_invocation_return_gerror (g_steal_pointer (&invocation), error);
      return G_DBUS_METHOD_INVOCATION_HANDLED;
    }

  request = dex_await_object (xdp_request_dex_new (credential->context, app_info, G_DBUS_INTERFACE_SKELETON (object),
                                                   G_DBUS_PROXY (credential->impl), frontend_options),
                              &error);
  if (!request)
    {
      g_dbus_method_invocation_return_gerror (g_steal_pointer (&invocation), error);
      return G_DBUS_METHOD_INVOCATION_HANDLED;
    }

  xdp_dbus_experimental_credential_complete_create_credential (object, invocation,
                                                               xdp_request_dex_get_object_path (request));

  handle_credential_request (credential, request, CREDENTIAL_OPERATION_PUBLIC_KEY_CREATE, arg_parent_window, arg_origin,
                             top_origin, request_json, backend_options_dict, app_id);

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
 * @frontend_options: (transfer none): options passed to the frontend.
 * @backend_options: (transfer none): options passed to the frontend.
 * @top_origin: (transfer none): pointer to string to top_origin field. May be
 * NULL.
 * @error: (transfer none): pointer to an error pointer that will be populated
 * on error. Returns: A boolean when options are successfully validated.
 */
static gboolean
get_credential_validate_options (GVariant *arg_options, GVariant **frontend_options, GVariantDict **backend_options,
                                 gchar **top_origin, GError **error)
{
  g_auto (GVariantBuilder) options = G_VARIANT_BUILDER_INIT (G_VARIANT_TYPE_VARDICT);
  g_autofree gchar *json = NULL;
  g_autofree gchar *top_origin_tmp = NULL;
  g_autoptr (GVariantDict) backend_options_dict = NULL;

  if (!xdp_filter_options (arg_options, &options, get_credential_options, G_N_ELEMENTS (get_credential_options), NULL,
                           error))
    {
      return FALSE;
    }

  if (!g_variant_lookup (arg_options, "public_key", "*", NULL))
    {
      g_set_error (error, XDG_DESKTOP_PORTAL_ERROR, XDG_DESKTOP_PORTAL_ERROR_INVALID_ARGUMENT,
                   "Parameters for at least one credential type must be passed in "
                   "`options` when retrieving a "
                   "credential. Current supported credential types are: `public_key`");
      return FALSE;
    };

  {
    backend_options_dict = g_variant_dict_new (NULL);

    g_autofree gchar *activation_token = NULL;
    // TODO: I don't think this else statement is necessary; check bug in
    // credentialsd
    if (g_variant_lookup (arg_options, "activation_token", "s", &activation_token))
      g_variant_dict_insert (backend_options_dict, "activation_token", "s", activation_token);
    else
      g_variant_dict_insert (backend_options_dict, "activation_token", "s", "");

    if (!g_variant_lookup (arg_options, "top_origin", "s", &top_origin_tmp))
      top_origin_tmp = g_strdup ("");
    g_variant_dict_insert (backend_options_dict, "top_origin", "s", top_origin_tmp);
  }

  *frontend_options = g_variant_ref_sink (g_variant_builder_end (&options));
  *backend_options = g_steal_pointer (&backend_options_dict);
  *top_origin = g_steal_pointer (&top_origin_tmp);
  return TRUE;
}

static gboolean
handle_get_credential (XdpDbusExperimentalCredential *object, GDBusMethodInvocation *invocation,
                       const gchar *arg_parent_window, const gchar *arg_origin, GVariant *arg_options)
{
  XdpCredential *credential = XDP_CREDENTIAL (object);
  g_autoptr (XdpRequestDex) request = NULL;
  g_autoptr (GError) error = NULL;
  g_autoptr (GVariant) frontend_options = NULL;
  g_autoptr (GVariantDict) backend_options_dict = NULL;
  g_autofree gchar *top_origin = NULL;
  g_autoptr (XdpCredentialRequestGuard) guard = NULL;

  if (!xdp_credential_guard_request (credential, &guard, &error))
    {
      g_dbus_method_invocation_return_gerror (g_steal_pointer (&invocation), error);
      return G_DBUS_METHOD_INVOCATION_HANDLED;
    };

  XdpAppInfo *app_info = xdp_invocation_get_app_info (invocation);
  const gchar *app_id = xdp_app_info_get_id (app_info);

  gboolean is_validated
    = get_credential_validate_options (arg_options, &frontend_options, &backend_options_dict, &top_origin, &error);

  if (!is_validated)
    {
      g_dbus_method_invocation_return_gerror (g_steal_pointer (&invocation), error);
      return G_DBUS_METHOD_INVOCATION_HANDLED;
    }

  request = dex_await_object (xdp_request_dex_new (credential->context, app_info, G_DBUS_INTERFACE_SKELETON (object),
                                                   G_DBUS_PROXY (credential->impl), frontend_options),
                              &error);
  if (!request)
    {
      g_dbus_method_invocation_return_gerror (g_steal_pointer (&invocation), error);
      return G_DBUS_METHOD_INVOCATION_HANDLED;
    }

  xdp_dbus_experimental_credential_complete_get_credential (object, invocation,
                                                            xdp_request_dex_get_object_path (request));

  handle_credential_request (credential, request, CREDENTIAL_OPERATION_PUBLIC_KEY_GET, arg_parent_window, arg_origin,
                             top_origin, frontend_options, backend_options_dict, app_id);

  return G_DBUS_METHOD_INVOCATION_HANDLED;
}

DexFuture *
init_credential (gpointer user_data)
{
  g_info ("Initializing Credential Portal");

  quark_credentialsd_error = g_quark_from_static_string ("-credentialsd-error");

  XdpContext *context = XDP_CONTEXT (user_data);
  g_autoptr (XdpCredential) credential = NULL;
  g_autoptr (CredentialsdDbusExperimentalManager) manager = NULL;
  g_autoptr (XdpDbusExperimentalImplCredential) impl = NULL;
  g_autoptr (GError) error = NULL;
  g_autoptr (XdpDbusExperimentalImplCredentialSignalMonitor) impl_signal_monitor = NULL;

  GDBusConnection *connection = xdp_context_get_connection (context);
  {
    XdpPortalConfig *config = xdp_context_get_config (context);
    XdpImplConfig *impl_config;

    impl_config = xdp_portal_config_find (config, CREDENTIAL_EXPERIMENTAL_DBUS_IMPL_IFACE);

    if (impl_config == NULL)
      {
        g_debug ("impl_config is NULL");
        return dex_future_new_true ();
      }

    g_debug ("found impl");

    impl = dex_await_object (xdp_dbus_experimental_impl_credential_proxy_new_future (
                               connection, G_DBUS_PROXY_FLAGS_NONE, impl_config->dbus_name, DESKTOP_DBUS_PATH),
                             &error);

    if (!impl)
      {
        if (!g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
          g_warning ("Failed to create credential proxy: %s", error->message);
        return dex_future_new_false ();
      }
  }

  g_debug ("creating credentialsd manager proxy...");

  manager = dex_await_object (
    credentialsd_dbus_experimental_manager_proxy_new_future (
      connection, G_DBUS_PROXY_FLAGS_NONE, CREDENTIALSD_DBUS_NAME, "/xyz/iinuwa/credentialsd/Manager"),
    &error);
  if (manager == NULL)
    {
      g_warning ("Failed to create credentialsd manager proxy: %s", error->message);
      return dex_future_new_false ();
    }
  g_debug ("created credentialsd manager proxy.");

  credential = xdp_credential_new (context, g_steal_pointer (&impl), g_steal_pointer (&manager));

  xdp_context_take_and_export_portal (context, G_DBUS_INTERFACE_SKELETON (g_steal_pointer (&credential)),
                                      XDP_CONTEXT_EXPORT_FLAGS_RUN_IN_FIBER);

  return dex_future_new_true ();
}

#undef DEFINE_CREDENTIALSD_SIGNAL_CB
