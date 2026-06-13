// Copyright 2025 The ArjunBrowser Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Handshake Integration Tests — validates the full 9-state machine.

#include "testing/gtest/include/gtest/gtest.h"

#include "net/pqc/pqc_handshake_state_machine.h"
#include "net/pqc/pqc_key_manager.h"
#include "net/pqc/quantum_security_module.h"

namespace net {
namespace pqc {
namespace {

// Test observer to capture state transitions
class TestObserver : public PQCSecurityPanelObserver {
public:
  void OnHandshakeStateChanged(const StateTransition &t) override {
    transitions.push_back(t);
  }
  void OnHandshakeCompleted(const PQCSessionRecord &r) override {
    completed = true;
    record = r;
  }
  void OnHandshakeFailed(const std::string &reason,
                         PKIVerificationResult result) override {
    failed = true;
    fail_reason = reason;
    fail_result = result;
  }

  std::vector<StateTransition> transitions;
  bool completed = false;
  bool failed = false;
  PQCSessionRecord record;
  std::string fail_reason;
  PKIVerificationResult fail_result;
};

// ═══════════════════════════════════════════════════════════════

class PQCHandshakeTest : public ::testing::Test {
protected:
  void SetUp() override { ASSERT_TRUE(QuantumSecurityModule::IsAvailable()); }
};

TEST_F(PQCHandshakeTest, InitialState) {
  PQCHandshakeStateMachine sm;
  EXPECT_EQ(sm.GetCurrentState(), HandshakeState::BROWSER_IDLE);
  EXPECT_FALSE(sm.IsCompleted());
  EXPECT_FALSE(sm.IsFailed());
  EXPECT_EQ(sm.GetPKIResult(), PKIVerificationResult::PENDING);
}

TEST_F(PQCHandshakeTest, FullHybridHandshakeWithIndigenousCA) {
  PQCHandshakeStateMachine sm;
  TestObserver observer;
  sm.AddObserver(&observer);

  sm.SetIndigenousMode(IndigenousMode::STRICT_FAIL_CLOSED);

  // Start the handshake
  sm.Start("https://army.mil.in/");

  // At this point the state machine has auto-progressed to
  // WAITING_FOR_SERVER (DNS resolved, keys generated, ClientHello sent)
  // Now simulate server verification
  sm.ProcessEvent(HandshakeEvent::PKI_VERIFIED_INDIGENOUS);

  // Should now be in SECURE_TUNNEL
  EXPECT_EQ(sm.GetCurrentState(), HandshakeState::SECURE_TUNNEL);
  EXPECT_TRUE(sm.IsCompleted());
  EXPECT_FALSE(sm.IsFailed());
  EXPECT_EQ(sm.GetPKIResult(), PKIVerificationResult::VERIFIED_INDIGENOUS);
  EXPECT_TRUE(sm.IsIndigenousVerified());

  // Verify state history contains expected transitions
  const auto &history = sm.GetStateHistory();
  EXPECT_GE(history.size(), 5u);

  // Verify observer was notified
  EXPECT_TRUE(observer.completed);
  EXPECT_FALSE(observer.failed);
  EXPECT_EQ(observer.record.domain, "army.mil.in");

  sm.RemoveObserver(&observer);
}

TEST_F(PQCHandshakeTest, FailClosedOnForeignCA) {
  PQCHandshakeStateMachine sm;
  TestObserver observer;
  sm.AddObserver(&observer);

  sm.SetIndigenousMode(IndigenousMode::STRICT_FAIL_CLOSED);

  // Start handshake to a foreign domain
  sm.Start("https://example.com/");

  // Simulate server presenting a foreign (non-indigenous) CA
  sm.ProcessEvent(HandshakeEvent::PKI_VERIFIED_EXTERNAL);

  // Must reach ALERT_SENT → CONNECTION_TERMINATED (Fail-Closed)
  EXPECT_EQ(sm.GetCurrentState(), HandshakeState::CONNECTION_TERMINATED);
  EXPECT_TRUE(sm.IsCompleted());
  EXPECT_TRUE(sm.IsFailed());
  EXPECT_EQ(sm.GetPKIResult(), PKIVerificationResult::FAILED_UNKNOWN_CA);
  EXPECT_FALSE(sm.IsIndigenousVerified());

  // Observer should report failure
  EXPECT_TRUE(observer.failed);
  EXPECT_FALSE(observer.completed);

  sm.RemoveObserver(&observer);
}

TEST_F(PQCHandshakeTest, PermissiveModeAllowsForeignCA) {
  PQCHandshakeStateMachine sm;

  sm.SetIndigenousMode(IndigenousMode::PERMISSIVE);
  sm.Start("https://example.com/");

  // Foreign CA in permissive mode should be allowed
  sm.ProcessEvent(HandshakeEvent::PKI_VERIFIED_EXTERNAL);

  EXPECT_EQ(sm.GetCurrentState(), HandshakeState::SECURE_TUNNEL);
  EXPECT_TRUE(sm.IsCompleted());
  EXPECT_FALSE(sm.IsFailed());
  EXPECT_EQ(sm.GetPKIResult(), PKIVerificationResult::VERIFIED_EXTERNAL);
  EXPECT_FALSE(sm.IsIndigenousVerified());
}

TEST_F(PQCHandshakeTest, PKIFailureTerminatesConnection) {
  PQCHandshakeStateMachine sm;

  sm.Start("https://malicious.example/");
  sm.ProcessEvent(HandshakeEvent::PKI_FAILED);

  EXPECT_EQ(sm.GetCurrentState(), HandshakeState::CONNECTION_TERMINATED);
  EXPECT_TRUE(sm.IsFailed());
}

TEST_F(PQCHandshakeTest, SessionRecordPopulated) {
  PQCHandshakeStateMachine sm;
  sm.Start("https://drdo.gov.in/");
  sm.ProcessEvent(HandshakeEvent::PKI_VERIFIED_INDIGENOUS);

  const auto &record = sm.GetSessionRecord();
  EXPECT_EQ(record.domain, "drdo.gov.in");
  EXPECT_EQ(record.port, 443);
  EXPECT_EQ(record.kem_algorithm, "ML-KEM-768");
  EXPECT_EQ(record.sig_algorithm, "ML-DSA-65");
  EXPECT_EQ(record.cipher_suite, "TLS_KYBER768_X25519_AES256GCM_SHA384");
  EXPECT_TRUE(record.hybrid_mode);
  EXPECT_EQ(record.tls_version, "TLS 1.3");
  EXPECT_EQ(record.status, HandshakeStatus::COMPLETED);
  EXPECT_FALSE(record.handshake_id.empty());
  EXPECT_FALSE(record.session_id.empty());
}

TEST_F(PQCHandshakeTest, URLParsing) {
  {
    PQCHandshakeStateMachine sm;
    sm.Start("https://army.mil.in:8443/path");
    EXPECT_EQ(sm.GetDomain(), "army.mil.in");
  }
  {
    PQCHandshakeStateMachine sm;
    sm.Start("https://defence.gov.in/");
    EXPECT_EQ(sm.GetDomain(), "defence.gov.in");
  }
  {
    PQCHandshakeStateMachine sm;
    sm.Start("https://nic.in");
    EXPECT_EQ(sm.GetDomain(), "nic.in");
  }
}

TEST_F(PQCHandshakeTest, KeyManagerIntegration) {
  PQCKeyManager key_manager(3);
  key_manager.Initialize();
  EXPECT_GE(key_manager.PoolSize(), 1u);

  PQCHandshakeStateMachine sm;
  sm.SetKeyManager(&key_manager);
  sm.Start("https://army.mil.in/");

  // Key should have been consumed from the pool
  EXPECT_GE(key_manager.TotalKeysGenerated(), 1u);
  EXPECT_TRUE(sm.GetKeyPair().IsValid());
}

TEST_F(PQCHandshakeTest, StateHistoryRecorded) {
  PQCHandshakeStateMachine sm;
  sm.Start("https://army.mil.in/");
  sm.ProcessEvent(HandshakeEvent::PKI_VERIFIED_INDIGENOUS);

  const auto &history = sm.GetStateHistory();
  EXPECT_FALSE(history.empty());

  // Each transition should have valid timestamps
  for (const auto &t : history) {
    EXPECT_FALSE(t.description.empty());
    EXPECT_GE(t.duration.InMicroseconds(), 0);
  }
}

TEST_F(PQCHandshakeTest, TabClosedTerminatesSecureTunnel) {
  PQCHandshakeStateMachine sm;
  sm.Start("https://army.mil.in/");
  sm.ProcessEvent(HandshakeEvent::PKI_VERIFIED_INDIGENOUS);
  EXPECT_EQ(sm.GetCurrentState(), HandshakeState::SECURE_TUNNEL);

  sm.ProcessEvent(HandshakeEvent::TAB_CLOSED);
  EXPECT_EQ(sm.GetCurrentState(), HandshakeState::CONNECTION_TERMINATED);
}

TEST_F(PQCHandshakeTest, NetworkErrorTerminatesSecureTunnel) {
  PQCHandshakeStateMachine sm;
  sm.Start("https://army.mil.in/");
  sm.ProcessEvent(HandshakeEvent::PKI_VERIFIED_INDIGENOUS);
  EXPECT_EQ(sm.GetCurrentState(), HandshakeState::SECURE_TUNNEL);

  sm.ProcessEvent(HandshakeEvent::NETWORK_ERROR);
  EXPECT_EQ(sm.GetCurrentState(), HandshakeState::CONNECTION_TERMINATED);
}

} // namespace
} // namespace pqc
} // namespace net
