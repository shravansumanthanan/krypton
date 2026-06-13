// Copyright 2025 The ArjunBrowser Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// PQC Key Manager — Pre-generated keypair pool for 0-RTT optimization.
//
// Per the DA3 STD specification: "The browser speculatively generates a
// Hybrid Keypair... By generating these keys immediately and sending them
// in the first packet (ClientHello), the browser reduces latency (0-RTT)."
//
// This class maintains a pool of pre-generated hybrid keypairs. When a
// new TLS connection is initiated, a keypair is consumed from the pool
// and the pool is asynchronously refilled in the background.

#ifndef NET_PQC_PQC_KEY_MANAGER_H_
#define NET_PQC_PQC_KEY_MANAGER_H_

#include <cstddef>
#include <deque>
#include <memory>
#include <mutex>

#include "base/memory/ref_counted.h"
#include "base/sequence_checker.h"
#include "base/task/sequenced_task_runner.h"
#include "base/timer/timer.h"
#include "net/pqc/quantum_security_module.h"

namespace net {
namespace pqc {

class PQCKeyManager {
public:
  // Default pool size — number of pre-generated keypairs to maintain.
  static constexpr int kDefaultKeyPoolSize = 5;

  // Maximum pool size — hard limit to prevent excessive memory usage.
  // Each hybrid keypair is ~3.6 KB (1184 + 2400 + 32 + 32 bytes).
  static constexpr int kMaxKeyPoolSize = 20;

  // Key expiry time — keypairs older than this are discarded.
  static constexpr base::TimeDelta kKeyExpiry = base::Minutes(30);

  explicit PQCKeyManager(int pool_size = kDefaultKeyPoolSize);
  ~PQCKeyManager();

  // Non-copyable
  PQCKeyManager(const PQCKeyManager &) = delete;
  PQCKeyManager &operator=(const PQCKeyManager &) = delete;

  // Initialize the key pool. Must be called on startup.
  // This generates |pool_size_| keypairs synchronously on first call,
  // then schedules background refill tasks.
  void Initialize();

  // Consume a keypair from the pool.
  // Returns a valid keypair, or an empty one if the pool is exhausted
  // (in which case a fresh keypair is generated synchronously).
  // Triggers a background refill task.
  HybridKeyPair ConsumeKey();

  // Returns the number of keypairs currently in the pool.
  size_t PoolSize() const;

  // Returns the total number of keypairs generated since startup.
  size_t TotalKeysGenerated() const { return total_generated_; }

  // Discard all keypairs from the pool and regenerate.
  void FlushPool();

  // Set the target pool size (capped at kMaxKeyPoolSize).
  void SetPoolSize(int size);

private:
  // Refill the pool to the target size. Called on a background thread.
  void RefillPool();

  // Remove expired keypairs from the pool.
  void PurgeExpiredKeys();

  // Schedule a periodic purge of expired keys.
  void SchedulePurge();

  // Target number of keypairs to maintain.
  int pool_size_;

  // The keypair pool (FIFO).
  std::deque<HybridKeyPair> key_pool_;

  // Mutex protecting key_pool_ for thread-safe access.
  mutable std::mutex pool_mutex_;

  // Counter for total keypairs generated.
  size_t total_generated_ = 0;

  // Whether the pool has been initialized.
  bool initialized_ = false;

  // Timer for periodic key purge.
  std::unique_ptr<base::RepeatingTimer> purge_timer_;

  SEQUENCE_CHECKER(sequence_checker_);
};

} // namespace pqc
} // namespace net

#endif // NET_PQC_PQC_KEY_MANAGER_H_
