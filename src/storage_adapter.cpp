#include "ezone/storage_adapter.h"
#include <algorithm>

namespace ezone {

// ─── Users ────────────────────────────────────────────────────────────────────

Result<void> MemoryStorageAdapter::create_user(const UserRecord& user) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (users_by_id_.count(user.user_id))
        return Result<void>::failure("user_id already exists: " + user.user_id);

    if (email_to_id_.count(user.email))
        return Result<void>::failure("email already registered: " + user.email);

    users_by_id_[user.user_id] = user;
    email_to_id_[user.email]   = user.user_id;
    return Result<void>::success();
}

Result<UserRecord> MemoryStorageAdapter::get_user_by_id(const std::string& user_id) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = users_by_id_.find(user_id);
    if (it == users_by_id_.end())
        return Result<UserRecord>::failure("user not found: " + user_id);

    return Result<UserRecord>::success(it->second);
}

Result<UserRecord> MemoryStorageAdapter::get_user_by_email(const std::string& email) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto eid = email_to_id_.find(email);
    if (eid == email_to_id_.end())
        return Result<UserRecord>::failure("email not found: " + email);

    auto uid = users_by_id_.find(eid->second);
    if (uid == users_by_id_.end())
        return Result<UserRecord>::failure("user record missing for email: " + email);

    return Result<UserRecord>::success(uid->second);
}

Result<void> MemoryStorageAdapter::deactivate_user(const std::string& user_id) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = users_by_id_.find(user_id);
    if (it == users_by_id_.end())
        return Result<void>::failure("user not found: " + user_id);

    it->second.active = false;
    return Result<void>::success();
}


// ─── Devices ──────────────────────────────────────────────────────────────────

Result<void> MemoryStorageAdapter::add_device(const DeviceRecord& dev) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (devices_.count(dev.device_id))
        return Result<void>::failure("device already exists: " + dev.device_id);

    devices_[dev.device_id] = dev;
    user_devices_[dev.user_id].push_back(dev.device_id);
    return Result<void>::success();
}

Result<std::vector<DeviceRecord>> MemoryStorageAdapter::get_devices(
    const std::string& user_id)
{
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<DeviceRecord> out;
    auto it = user_devices_.find(user_id);
    if (it == user_devices_.end())
        return Result<std::vector<DeviceRecord>>::success(out);

    for (const auto& dev_id : it->second) {
        auto dit = devices_.find(dev_id);
        if (dit != devices_.end())
            out.push_back(dit->second);
    }
    return Result<std::vector<DeviceRecord>>::success(std::move(out));
}

Result<DeviceRecord> MemoryStorageAdapter::get_device(const std::string& device_id) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = devices_.find(device_id);
    if (it == devices_.end())
        return Result<DeviceRecord>::failure("device not found: " + device_id);

    return Result<DeviceRecord>::success(it->second);
}

Result<void> MemoryStorageAdapter::revoke_device(const std::string& device_id) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = devices_.find(device_id);
    if (it == devices_.end())
        return Result<void>::failure("device not found: " + device_id);

    it->second.revoked = true;
    return Result<void>::success();
}


// ─── Recovery codes ───────────────────────────────────────────────────────────

Result<void> MemoryStorageAdapter::store_recovery_hash(
    const std::string& user_id,
    const std::string& code_hash)
{
    std::lock_guard<std::mutex> lock(mutex_);
    recovery_hashes_[user_id].insert(code_hash);
    return Result<void>::success();
}

Result<bool> MemoryStorageAdapter::consume_recovery_hash(
    const std::string& user_id,
    const std::string& code_hash)
{
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = recovery_hashes_.find(user_id);
    if (it == recovery_hashes_.end())
        return Result<bool>::success(false);

    auto cit = it->second.find(code_hash);
    if (cit == it->second.end())
        return Result<bool>::success(false);

    it->second.erase(cit);
    return Result<bool>::success(true);
}

Result<void> MemoryStorageAdapter::clear_recovery_hashes(const std::string& user_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    recovery_hashes_.erase(user_id);
    return Result<void>::success();
}

} // namespace ezone
