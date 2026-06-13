// Copyright 2025 The ArjunBrowser Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/pqc/pqc_key_manager.h"

#include "base/logging.h"
#include "base/task/thread_pool.h"
#include "base/time/time.h"

namespace net {
namespace pqc {

PQCKeyManager::PQCKeyManager(int pool_size)
    : pool_size_(std::min(pool_size, kMaxKeyPoolSize)) {
  DETACH_FROM_SEQUENCE(sequence_checker_);
}

PQCKeyManager::~PQCKeyManager() {
  // Clear all secrets from the pool
  std::lock_guard<std::mutex> lock(pool_mutex_);
  for (auto &kp : key_pool_) {
    kp.ClearSecrets();
  }
  key_pool_.clear();
}

void PQCKeyManager::Initialize() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  if (initialized_) {
    return;
  }

  LOG(INFO) << "PQCKeyManager: Initializing with pool size " << pool_size_;

  // Generate initial pool synchronously
  RefillPool();

  // Schedule periodic purge of expired keys (every 5 minutes)
  SchedulePurge();

  initialized_ = true;
  LOG(INFO) << "PQCKeyManager: Initialized with " << PoolSize()
            << " pre-generated hybrid keypairs.";
}

HybridKeyPair PQCKeyManager::ConsumeKey() {
  std::lock_guard<std::mutex> lock(pool_mutex_);

  // Try to get a keypair from the pool
  if (!key_pool_.empty()) {
    HybridKeyPair key = std::move(key_pool_.front());
    key_pool_.pop_front();

    // Check if key is expired
    if (base::Time::Now() - key.generated_at > kKeyExpiry) {
      key.ClearSecrets();
      VLOG(1) << "PQCKeyManager: Discarded expired key, generating fresh.";
    } else {
      VLOG(1) << "PQCKeyManager: Consumed key " << key.key_id << " from pool. "
              << key_pool_.size() << " remaining.";

      // Trigger background refill
      base::ThreadPool::PostTask(
          FROM_HERE, {base::TaskPriority::BEST_EFFORT, base::MayBlock()},
          base::BindOnce(&PQCKeyManager::RefillPool, base::Unretained(this)));
      return key;
    }
  }

  // Pool exhausted — generate fresh keypair synchronously
  LOG(WARNING) << "PQCKeyManager: Pool exhausted, generating keypair "
               << "synchronously (may add latency).";
  HybridKeyPair fresh = QuantumSecurityModule::GenerateHybridKeypair();
  total_generated_++;

  // Trigger background refill
  base::ThreadPool::PostTask(
      FROM_HERE, {base::TaskPriority::BEST_EFFORT, base::MayBlock()},
      base::BindOnce(&PQCKeyManager::RefillPool, base::Unretained(this)));

  return fresh;
}

size_t PQCKeyManager::PoolSize() const {
  std::lock_guard<std::mutex> lock(pool_mutex_);
  return key_pool_.size();
}

void PQCKeyManager::FlushPool() {
  std::lock_guard<std::mutex> lock(pool_mutex_);
  for (auto &kp : key_pool_) {
    kp.ClearSecrets();
  }
  key_pool_.clear();

  VLOG(1) << "PQCKeyManager: Pool flushed. Regenerating...";

  // Unlock before generating to avoid holding lock during keygen
  pool_mutex_.unlock();
  RefillPool();
  pool_mutex_.lock();
}

void PQCKeyManager::SetPoolSize(int size) {
  pool_size_ = std::min(size, kMaxKeyPoolSize);
  VLOG(1) << "PQCKeyManager: Pool size set to " << pool_size_;
}

void PQCKeyManager::RefillPool() {
  std::lock_guard<std::mutex> lock(pool_mutex_);

  while (static_cast<int>(key_pool_.size()) < pool_size_) {
    HybridKeyPair kp = QuantumSecurityModule::GenerateHybridKeypair();
    if (kp.IsValid()) {
      key_pool_.push_back(std::move(kp));
      total_generated_++;
    } else {
      LOG(ERROR) << "PQCKeyManager: Failed to generate keypair during refill.";
      break;
    }
  }

  VLOG(2) << "PQCKeyManager: Pool refilled to " << key_pool_.size()
          << " keypairs. Total generated: " << total_generated_;
}

void PQCKeyManager::PurgeExpiredKeys() {
  std::lock_guard<std::mutex> lock(pool_mutex_);

  auto now = base::Time::Now();
  size_t before = key_pool_.size();

  key_pool_.erase(
      std::remove_if(key_pool_.begin(), key_pool_.end(),
                     [&now](const HybridKeyPair &kp) {
                       if (now - kp.generated_at > kKeyExpiry) {
                         // const_cast needed for ClearSecrets
                         const_cast<HybridKeyPair &>(kp).ClearSecrets();
                         return true;
                       }
                       return false;
                     }),
      key_pool_.end());

  size_t purged = before - key_pool_.size();
  if (purged > 0) {
    VLOG(1) << "PQCKeyManager: Purged " << purged << " expired keys.";
  }
}

void PQCKeyManager::SchedulePurge() {
  // Periodic purge every 5 minutes
  purge_timer_ = std::make_unique<base::RepeatingTimer>();
  purge_timer_->Start(FROM_HERE, base::Minutes(5),
                      base::BindRepeating(&PQCKeyManager::PurgeExpiredKeys,
                                          base::Unretained(this)));
}

} // namespace pqc
} // namespace net
