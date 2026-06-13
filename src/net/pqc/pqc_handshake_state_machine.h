// Copyright 2025 The ArjunBrowser Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// PQC Handshake State Machine — Full 9-state UML State Machine
// from the DA3 State Transition Diagram.
//
// States:
//   BROWSER_IDLE → RESOLVING_DNS → KEY_GENERATION → WAITING_FOR_SERVER
//   → VERIFYING_IDENTITY → [DECISION NODE]
//     → DERIVING_SECRETS → SECURE_TUNNEL → CONNECTION_TERMINATED
//     → ALERT_SENT → CONNECTION_TERMINATED
//
// Each state transition:
//   1. Updates current_state_
//   2. Writes a log entry to the tls_handshakes SQLite table
//   3. Emits a base::trace_event for performance tracing
//   4. Notifies the browser UI via PQCSecurityPanelObserver

#ifndef NET_PQC_PQC_HANDSHAKE_STATE_MACHINE_H_
#define NET_PQC_PQC_HANDSHAKE_STATE_MACHINE_H_

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "base/observer_list.h"
#include "base/time/time.h"
#include "net/cert/pqc_certificate_validator.h"
#include "net/cert/pqc_indigenous_trust_store.h"
#include "net/pqc/pqc_key_manager.h"
#include "net/pqc/pqc_session_record.h"
#include "net/pqc/quantum_security_module.h"

namespace net {
namespace pqc {

// ─── Handshake State Enum (9 states) ────────────────────────

enum class HandshakeState {
  BROWSER_IDLE,       // Initial state: waiting for URL input
  RESOLVING_DNS,      // DNS-over-HTTPS query in progress
  KEY_GENERATION,     // Speculatively generating X25519 + ML-KEM-768
  WAITING_FOR_SERVER, // ClientHello sent, awaiting ServerHello
  VERIFYING_IDENTITY, // Parsing and verifying server certificate
  // ── DECISION NODE ──
  DERIVING_SECRETS, // Path A: PKI OK → HKDF hybrid key derivation
  ALERT_SENT,       // Path B: PKI FAIL → TLS fatal alert + disconnect
  // ── POST-HANDSHAKE ──
  SECURE_TUNNEL,         // AES-256-GCM active, traffic flowing
  CONNECTION_TERMINATED, // TCP closed (error or user-initiated)
};

// Events that trigger state transitions
enum class HandshakeEvent {
  URL_ENTERED,
  IP_RESOLVED,
  DNS_FAILED,
  KEYS_READY,
  SERVER_HELLO_RECEIVED,
  TIMEOUT,
  PKI_VERIFIED_INDIGENOUS,
  PKI_VERIFIED_EXTERNAL,
  PKI_FAILED,
  KEYS_DERIVED,
  ALERT_SENT,
  TAB_CLOSED,
  NETWORK_ERROR,
};

// Indigenous PKI mode
enum class IndigenousMode {
  STRICT_FAIL_CLOSED, // Reject non-indigenous chains
  PERMISSIVE,         // Allow with warning
};

// ─── State Transition Log Entry ─────────────────────────────

struct StateTransition {
  HandshakeState from_state;
  HandshakeState to_state;
  HandshakeEvent trigger_event;
  base::Time timestamp;
  base::TimeDelta duration; // Time spent in from_state
  std::string description;
};

// ─── Observer Interface ─────────────────────────────────────

class PQCSecurityPanelObserver : public base::CheckedObserver {
public:
  virtual void OnHandshakeStateChanged(const StateTransition &transition) = 0;
  virtual void OnHandshakeCompleted(const PQCSessionRecord &record) = 0;
  virtual void OnHandshakeFailed(const std::string &reason,
                                 PKIVerificationResult result) = 0;
};

// ─── PQCHandshakeStateMachine ───────────────────────────────

class PQCHandshakeStateMachine {
public:
  PQCHandshakeStateMachine();
  ~PQCHandshakeStateMachine();

  // Start a new handshake for the given URL.
  void Start(const std::string &url);

  // Process an event, potentially triggering a state transition.
  void ProcessEvent(HandshakeEvent event);

  // Set Indigenous PKI mode.
  void SetIndigenousMode(IndigenousMode mode);

  // Set the key manager for 0-RTT key consumption.
  void SetKeyManager(PQCKeyManager *key_manager);

  // ── State Query ──

  HandshakeState GetCurrentState() const { return current_state_; }
  HandshakeState GetFinalState() const;
  PKIVerificationResult GetPKIResult() const { return pki_result_; }
  bool IsIndigenousVerified() const;
  bool IsCompleted() const;
  bool IsFailed() const;

  // Get the full state transition history.
  const std::vector<StateTransition> &GetStateHistory() const;

  // Get the session record for this handshake.
  const PQCSessionRecord &GetSessionRecord() const { return session_record_; }

  // ── Observer Management ──

  void AddObserver(PQCSecurityPanelObserver *observer);
  void RemoveObserver(PQCSecurityPanelObserver *observer);

  // ── Handshake Data ──

  // Get the hybrid keypair used in this handshake
  const HybridKeyPair &GetKeyPair() const { return keypair_; }

  // Get the derived session key
  const HybridSessionKey &GetSessionKey() const { return session_key_; }

  // Get the target URL/domain
  const std::string &GetDomain() const { return domain_; }

  // Get handshake duration so far
  base::TimeDelta GetElapsedTime() const;

private:
  // ── State Transition Handlers ──

  void TransitionTo(HandshakeState new_state, HandshakeEvent event,
                    const std::string &description = "");

  // Individual state handlers
  void HandleBrowserIdle(HandshakeEvent event);
  void HandleResolvingDNS(HandshakeEvent event);
  void HandleKeyGeneration(HandshakeEvent event);
  void HandleWaitingForServer(HandshakeEvent event);
  void HandleVerifyingIdentity(HandshakeEvent event);
  void HandleDerivingSecrets(HandshakeEvent event);
  void HandleAlertSent(HandshakeEvent event);
  void HandleSecureTunnel(HandshakeEvent event);

  // Validate that a transition is legal
  bool IsValidTransition(HandshakeState from, HandshakeState to,
                         HandshakeEvent event) const;

  // Notify all observers of a state change
  void NotifyObservers(const StateTransition &transition);

  // ── State ──

  HandshakeState current_state_ = HandshakeState::BROWSER_IDLE;
  IndigenousMode indigenous_mode_ = IndigenousMode::STRICT_FAIL_CLOSED;
  PKIVerificationResult pki_result_ = PKIVerificationResult::PENDING;

  // Timing
  base::Time handshake_start_;
  base::Time state_entry_time_;

  // Target
  std::string url_;
  std::string domain_;
  std::string ip_address_;
  uint16_t port_ = 443;

  // Cryptographic state
  HybridKeyPair keypair_;
  HybridSessionKey session_key_;

  // Key manager for 0-RTT (not owned)
  PQCKeyManager *key_manager_ = nullptr;

  // Session record
  PQCSessionRecord session_record_;

  // State transition history
  std::vector<StateTransition> state_history_;

  // Observers
  base::ObserverList<PQCSecurityPanelObserver> observers_;
};

// ── Utility Functions ──

// Convert state to string for logging/display
const char *HandshakeStateToString(HandshakeState state);

// Convert event to string for logging/display
const char *HandshakeEventToString(HandshakeEvent event);

} // namespace pqc
} // namespace net

#endif // NET_PQC_PQC_HANDSHAKE_STATE_MACHINE_H_
