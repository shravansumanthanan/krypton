// Copyright 2025 The ArjunBrowser Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/pqc/pqc_handshake_state_machine.h"

#include "base/logging.h"
#include "base/time/time.h"
#include "base/trace_event/trace_event.h"

namespace net {
namespace pqc {

// ─── String Conversion Utilities ────────────────────────────

const char *HandshakeStateToString(HandshakeState state) {
  switch (state) {
  case HandshakeState::BROWSER_IDLE:
    return "BROWSER_IDLE";
  case HandshakeState::RESOLVING_DNS:
    return "RESOLVING_DNS";
  case HandshakeState::KEY_GENERATION:
    return "KEY_GENERATION";
  case HandshakeState::WAITING_FOR_SERVER:
    return "WAITING_FOR_SERVER";
  case HandshakeState::VERIFYING_IDENTITY:
    return "VERIFYING_IDENTITY";
  case HandshakeState::DERIVING_SECRETS:
    return "DERIVING_SECRETS";
  case HandshakeState::ALERT_SENT:
    return "ALERT_SENT";
  case HandshakeState::SECURE_TUNNEL:
    return "SECURE_TUNNEL";
  case HandshakeState::CONNECTION_TERMINATED:
    return "CONNECTION_TERMINATED";
  }
  return "UNKNOWN";
}

const char *HandshakeEventToString(HandshakeEvent event) {
  switch (event) {
  case HandshakeEvent::URL_ENTERED:
    return "URL_ENTERED";
  case HandshakeEvent::IP_RESOLVED:
    return "IP_RESOLVED";
  case HandshakeEvent::DNS_FAILED:
    return "DNS_FAILED";
  case HandshakeEvent::KEYS_READY:
    return "KEYS_READY";
  case HandshakeEvent::SERVER_HELLO_RECEIVED:
    return "SERVER_HELLO_RECEIVED";
  case HandshakeEvent::TIMEOUT:
    return "TIMEOUT";
  case HandshakeEvent::PKI_VERIFIED_INDIGENOUS:
    return "PKI_VERIFIED_INDIGENOUS";
  case HandshakeEvent::PKI_VERIFIED_EXTERNAL:
    return "PKI_VERIFIED_EXTERNAL";
  case HandshakeEvent::PKI_FAILED:
    return "PKI_FAILED";
  case HandshakeEvent::KEYS_DERIVED:
    return "KEYS_DERIVED";
  case HandshakeEvent::ALERT_SENT:
    return "ALERT_SENT";
  case HandshakeEvent::TAB_CLOSED:
    return "TAB_CLOSED";
  case HandshakeEvent::NETWORK_ERROR:
    return "NETWORK_ERROR";
  }
  return "UNKNOWN";
}

// ─── PQCHandshakeStateMachine ───────────────────────────────

PQCHandshakeStateMachine::PQCHandshakeStateMachine()
    : current_state_(HandshakeState::BROWSER_IDLE),
      state_entry_time_(base::Time::Now()) {
  session_record_.kem_algorithm = "ML-KEM-768";
  session_record_.sig_algorithm = "ML-DSA-65";
  session_record_.cipher_suite = "TLS_KYBER768_X25519_AES256GCM_SHA384";
  session_record_.hybrid_mode = true;
  session_record_.tls_version = "TLS 1.3";
}

PQCHandshakeStateMachine::~PQCHandshakeStateMachine() {
  keypair_.ClearSecrets();
  session_key_.ClearSecrets();
}

void PQCHandshakeStateMachine::Start(const std::string &url) {
  TRACE_EVENT0("pqc", "PQCHandshakeStateMachine::Start");

  url_ = url;
  handshake_start_ = base::Time::Now();
  state_entry_time_ = handshake_start_;

  // Parse domain from URL
  // Simple parsing: extract host from https://host:port/path
  size_t scheme_end = url_.find("://");
  size_t host_start = (scheme_end != std::string::npos) ? scheme_end + 3 : 0;
  size_t host_end = url_.find('/', host_start);
  if (host_end == std::string::npos)
    host_end = url_.length();
  size_t port_pos = url_.find(':', host_start);
  if (port_pos != std::string::npos && port_pos < host_end) {
    domain_ = url_.substr(host_start, port_pos - host_start);
    std::string port_str = url_.substr(port_pos + 1, host_end - port_pos - 1);
    port_ = static_cast<uint16_t>(std::stoi(port_str));
  } else {
    domain_ = url_.substr(host_start, host_end - host_start);
    port_ = 443;
  }

  session_record_.domain = domain_;
  session_record_.port = port_;
  session_record_.handshake_id = QuantumSecurityModule::GenerateUUID();
  session_record_.session_id = QuantumSecurityModule::GenerateUUID();

  LOG(INFO) << "PQC Handshake: Starting for " << domain_ << ":" << port_;

  // Initial state entry
  session_record_.state_history.push_back(
      HandshakeStateToString(HandshakeState::BROWSER_IDLE));

  // Trigger the first transition
  ProcessEvent(HandshakeEvent::URL_ENTERED);
}

void PQCHandshakeStateMachine::ProcessEvent(HandshakeEvent event) {
  TRACE_EVENT2("pqc", "PQCHandshakeStateMachine::ProcessEvent", "state",
               HandshakeStateToString(current_state_), "event",
               HandshakeEventToString(event));

  VLOG(1) << "PQC Handshake: Event " << HandshakeEventToString(event)
          << " in state " << HandshakeStateToString(current_state_);

  switch (current_state_) {
  case HandshakeState::BROWSER_IDLE:
    HandleBrowserIdle(event);
    break;
  case HandshakeState::RESOLVING_DNS:
    HandleResolvingDNS(event);
    break;
  case HandshakeState::KEY_GENERATION:
    HandleKeyGeneration(event);
    break;
  case HandshakeState::WAITING_FOR_SERVER:
    HandleWaitingForServer(event);
    break;
  case HandshakeState::VERIFYING_IDENTITY:
    HandleVerifyingIdentity(event);
    break;
  case HandshakeState::DERIVING_SECRETS:
    HandleDerivingSecrets(event);
    break;
  case HandshakeState::ALERT_SENT:
    HandleAlertSent(event);
    break;
  case HandshakeState::SECURE_TUNNEL:
    HandleSecureTunnel(event);
    break;
  case HandshakeState::CONNECTION_TERMINATED:
    // Terminal state — no transitions
    VLOG(1) << "PQC Handshake: Already terminated, ignoring event.";
    break;
  }
}

// ─── State Transition ───────────────────────────────────────

void PQCHandshakeStateMachine::TransitionTo(HandshakeState new_state,
                                            HandshakeEvent event,
                                            const std::string &description) {
  base::Time now = base::Time::Now();
  base::TimeDelta duration = now - state_entry_time_;

  StateTransition transition;
  transition.from_state = current_state_;
  transition.to_state = new_state;
  transition.trigger_event = event;
  transition.timestamp = now;
  transition.duration = duration;
  transition.description = description.empty()
                               ? std::string(HandshakeEventToString(event))
                               : description;

  state_history_.push_back(transition);
  session_record_.state_history.push_back(HandshakeStateToString(new_state));

  LOG(INFO) << "PQC Handshake: " << HandshakeStateToString(current_state_)
            << " → " << HandshakeStateToString(new_state)
            << " (event: " << HandshakeEventToString(event)
            << ", duration: " << duration.InMilliseconds() << "ms)";

  TRACE_EVENT_INSTANT2("pqc", "StateTransition", TRACE_EVENT_SCOPE_THREAD,
                       "from", HandshakeStateToString(current_state_), "to",
                       HandshakeStateToString(new_state));

  current_state_ = new_state;
  state_entry_time_ = now;

  // Notify observers
  NotifyObservers(transition);
}

// ─── State Handlers ─────────────────────────────────────────

void PQCHandshakeStateMachine::HandleBrowserIdle(HandshakeEvent event) {
  if (event == HandshakeEvent::URL_ENTERED) {
    TransitionTo(HandshakeState::RESOLVING_DNS, event,
                 "DNS resolution initiated for " + domain_);

    // Simulate DNS resolution completing (in real impl, this would
    // be async via DNS-over-HTTPS)
    // For now, immediately trigger IP_RESOLVED
    ProcessEvent(HandshakeEvent::IP_RESOLVED);
  }
}

void PQCHandshakeStateMachine::HandleResolvingDNS(HandshakeEvent event) {
  switch (event) {
  case HandshakeEvent::IP_RESOLVED:
    ip_address_ = "10.0.0.1"; // Placeholder
    session_record_.ip_address = ip_address_;
    TransitionTo(HandshakeState::KEY_GENERATION, event,
                 "DNS resolved to " + ip_address_);

    // Generate keypair (or consume from pool)
    if (key_manager_) {
      keypair_ = key_manager_->ConsumeKey();
    } else {
      keypair_ = QuantumSecurityModule::GenerateHybridKeypair();
    }

    if (keypair_.IsValid()) {
      ProcessEvent(HandshakeEvent::KEYS_READY);
    } else {
      ProcessEvent(HandshakeEvent::NETWORK_ERROR);
    }
    break;

  case HandshakeEvent::DNS_FAILED:
    TransitionTo(HandshakeState::CONNECTION_TERMINATED, event,
                 "DNS resolution failed for " + domain_);
    session_record_.Fail(PKIVerificationResult::FAILED_UNKNOWN_CA,
                         "DNS resolution failed");
    break;

  default:
    VLOG(1) << "PQC Handshake: Unexpected event in RESOLVING_DNS";
    break;
  }
}

void PQCHandshakeStateMachine::HandleKeyGeneration(HandshakeEvent event) {
  switch (event) {
  case HandshakeEvent::KEYS_READY:
    TransitionTo(HandshakeState::WAITING_FOR_SERVER, event,
                 "Hybrid keypair generated (X25519 + ML-KEM-768). "
                 "ClientHello sent with key_share.");

    // In real implementation, the ClientHello would be sent here
    // with the concatenated public keys. For simulation, we
    // immediately process the server response.
    ProcessEvent(HandshakeEvent::SERVER_HELLO_RECEIVED);
    break;

  case HandshakeEvent::NETWORK_ERROR:
    TransitionTo(HandshakeState::CONNECTION_TERMINATED, event,
                 "Key generation failed");
    session_record_.Fail(PKIVerificationResult::FAILED_INVALID_SIG,
                         "Hybrid keypair generation failed");
    break;

  default:
    break;
  }
}

void PQCHandshakeStateMachine::HandleWaitingForServer(HandshakeEvent event) {
  switch (event) {
  case HandshakeEvent::SERVER_HELLO_RECEIVED:
    TransitionTo(HandshakeState::VERIFYING_IDENTITY, event,
                 "ServerHello received. Verifying server certificate.");
    break;

  case HandshakeEvent::TIMEOUT:
    TransitionTo(HandshakeState::CONNECTION_TERMINATED, event,
                 "Server did not respond within timeout period.");
    session_record_.Fail(PKIVerificationResult::FAILED_UNKNOWN_CA,
                         "Connection timeout");
    break;

  case HandshakeEvent::NETWORK_ERROR:
    TransitionTo(HandshakeState::CONNECTION_TERMINATED, event,
                 "Network error while waiting for ServerHello.");
    session_record_.Fail(PKIVerificationResult::FAILED_UNKNOWN_CA,
                         "Network error");
    break;

  default:
    break;
  }
}

void PQCHandshakeStateMachine::HandleVerifyingIdentity(HandshakeEvent event) {
  switch (event) {
  case HandshakeEvent::PKI_VERIFIED_INDIGENOUS:
    pki_result_ = PKIVerificationResult::VERIFIED_INDIGENOUS;
    TransitionTo(HandshakeState::DERIVING_SECRETS, event,
                 "Certificate verified: Indigenous PKI ✓");
    // Derive session key
    ProcessEvent(HandshakeEvent::KEYS_DERIVED);
    break;

  case HandshakeEvent::PKI_VERIFIED_EXTERNAL:
    if (indigenous_mode_ == IndigenousMode::STRICT_FAIL_CLOSED) {
      // Fail-Closed: treat external CA as failure
      pki_result_ = PKIVerificationResult::FAILED_UNKNOWN_CA;
      TransitionTo(HandshakeState::ALERT_SENT, event,
                   "External CA detected in Fail-Closed mode. "
                   "Connection rejected.");
      ProcessEvent(HandshakeEvent::ALERT_SENT);
    } else {
      // Permissive: allow with warning
      pki_result_ = PKIVerificationResult::VERIFIED_EXTERNAL;
      TransitionTo(HandshakeState::DERIVING_SECRETS, event,
                   "Certificate verified: External CA ⚠ (permissive mode)");
      ProcessEvent(HandshakeEvent::KEYS_DERIVED);
    }
    break;

  case HandshakeEvent::PKI_FAILED:
    pki_result_ = PKIVerificationResult::FAILED_INVALID_SIG;
    TransitionTo(HandshakeState::ALERT_SENT, event,
                 "Certificate verification FAILED. "
                 "Potential MitM attack detected.");
    ProcessEvent(HandshakeEvent::ALERT_SENT);
    break;

  default:
    break;
  }
}

void PQCHandshakeStateMachine::HandleDerivingSecrets(HandshakeEvent event) {
  if (event == HandshakeEvent::KEYS_DERIVED) {
    // Derive the hybrid session key
    std::vector<uint8_t> mock_x25519_shared(32, 0xAA);
    std::vector<uint8_t> mock_kem_shared(32, 0xBB);

    session_key_ = QuantumSecurityModule::DeriveSessionKey(mock_x25519_shared,
                                                           mock_kem_shared);

    base::TimeDelta elapsed = base::Time::Now() - handshake_start_;
    session_key_.indigenous_verified =
        (pki_result_ == PKIVerificationResult::VERIFIED_INDIGENOUS);

    session_record_.Complete(static_cast<int>(elapsed.InMilliseconds()),
                             pki_result_, session_key_.ca_name);

    TransitionTo(HandshakeState::SECURE_TUNNEL, event,
                 "Session key derived via HKDF-SHA3-256. "
                 "AES-256-GCM tunnel active.");

    // Notify observers of completion
    for (auto &observer : observers_) {
      observer.OnHandshakeCompleted(session_record_);
    }
  }
}

void PQCHandshakeStateMachine::HandleAlertSent(HandshakeEvent event) {
  if (event == HandshakeEvent::ALERT_SENT) {
    TransitionTo(HandshakeState::CONNECTION_TERMINATED, event,
                 "TLS fatal alert sent. Connection terminated.");

    session_record_.Fail(pki_result_,
                         "TLS alert sent: certificate validation failed");

    // Notify observers of failure
    for (auto &observer : observers_) {
      observer.OnHandshakeFailed(session_record_.state_history.back(),
                                 pki_result_);
    }
  }
}

void PQCHandshakeStateMachine::HandleSecureTunnel(HandshakeEvent event) {
  switch (event) {
  case HandshakeEvent::TAB_CLOSED:
    TransitionTo(HandshakeState::CONNECTION_TERMINATED, event,
                 "Tab closed. Secure tunnel terminated.");
    break;

  case HandshakeEvent::NETWORK_ERROR:
    TransitionTo(HandshakeState::CONNECTION_TERMINATED, event,
                 "Network error in secure tunnel.");
    break;

  default:
    break;
  }
}

// ─── Query Methods ──────────────────────────────────────────

void PQCHandshakeStateMachine::SetIndigenousMode(IndigenousMode mode) {
  indigenous_mode_ = mode;
}

void PQCHandshakeStateMachine::SetKeyManager(PQCKeyManager *key_manager) {
  key_manager_ = key_manager;
}

HandshakeState PQCHandshakeStateMachine::GetFinalState() const {
  if (state_history_.empty()) {
    return current_state_;
  }
  return current_state_;
}

bool PQCHandshakeStateMachine::IsIndigenousVerified() const {
  return pki_result_ == PKIVerificationResult::VERIFIED_INDIGENOUS;
}

bool PQCHandshakeStateMachine::IsCompleted() const {
  return current_state_ == HandshakeState::SECURE_TUNNEL ||
         current_state_ == HandshakeState::CONNECTION_TERMINATED;
}

bool PQCHandshakeStateMachine::IsFailed() const {
  return current_state_ == HandshakeState::CONNECTION_TERMINATED &&
         pki_result_ != PKIVerificationResult::VERIFIED_INDIGENOUS &&
         pki_result_ != PKIVerificationResult::VERIFIED_EXTERNAL;
}

const std::vector<StateTransition> &
PQCHandshakeStateMachine::GetStateHistory() const {
  return state_history_;
}

base::TimeDelta PQCHandshakeStateMachine::GetElapsedTime() const {
  return base::Time::Now() - handshake_start_;
}

void PQCHandshakeStateMachine::AddObserver(PQCSecurityPanelObserver *observer) {
  observers_.AddObserver(observer);
}

void PQCHandshakeStateMachine::RemoveObserver(
    PQCSecurityPanelObserver *observer) {
  observers_.RemoveObserver(observer);
}

void PQCHandshakeStateMachine::NotifyObservers(
    const StateTransition &transition) {
  for (auto &observer : observers_) {
    observer.OnHandshakeStateChanged(transition);
  }
}

} // namespace pqc
} // namespace net
