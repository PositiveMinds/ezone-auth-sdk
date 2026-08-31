#include "ezone/storage_adapter.h"
#include <algorithm>

namespace ezone {

// ─── Users ────────────────────────────────────────────────────────────────────

Result<void> MemoryStorageAdapter::create_user(const UserRecord& user) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (users_by_id_.count(user.user_id))
        return Result<void>::failure("user_id already exists: " + user.user_id);

    if (!user.email.empty() && email_to_id_.count(user.email))
        return Result<void>::failure("email already registered: " + user.email);

    if (!user.username.empty() && username_to_id_.count(user.username))
        return Result<void>::failure("username already taken: " + user.username);

    users_by_id_[user.user_id] = user;
    if (!user.email.empty())
        email_to_id_[user.email] = user.user_id;
    if (!user.username.empty())
        username_to_id_[user.username] = user.user_id;
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

Result<UserRecord> MemoryStorageAdapter::get_user_by_username(
    const std::string& username)
{
    std::lock_guard<std::mutex> lock(mutex_);

    auto uid = username_to_id_.find(username);
    if (uid == username_to_id_.end())
        return Result<UserRecord>::failure("username not found: " + username);

    auto it = users_by_id_.find(uid->second);
    if (it == users_by_id_.end())
        return Result<UserRecord>::failure("user record missing for username: " + username);

    return Result<UserRecord>::success(it->second);
}

Result<void> MemoryStorageAdapter::deactivate_user(const std::string& user_id) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = users_by_id_.find(user_id);
    if (it == users_by_id_.end())
        return Result<void>::failure("user not found: " + user_id);

    it->second.active = false;
    return Result<void>::success();
}

Result<void> MemoryStorageAdapter::update_user(const UserRecord& user) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = users_by_id_.find(user.user_id);
    if (it == users_by_id_.end())
        return Result<void>::failure("user not found: " + user.user_id);

    // Update username mapping if changed
    auto& old = it->second;
    if (!old.username.empty() && old.username != user.username)
        username_to_id_.erase(old.username);
    if (!user.username.empty())
        username_to_id_[user.username] = user.user_id;

    // Update email mapping if changed
    if (!old.email.empty() && old.email != user.email)
        email_to_id_.erase(old.email);
    if (!user.email.empty())
        email_to_id_[user.email] = user.user_id;

    it->second = user;
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


// ─── WebAuthn credentials ────────────────────────────────────────────────────

Result<void> MemoryStorageAdapter::add_webauthn_credential(
    const WebAuthnCredentialRecord& cred)
{
    std::lock_guard<std::mutex> lock(mutex_);

    if (webauthn_creds_.count(cred.credential_id))
        return Result<void>::failure("credential already exists: " + cred.credential_id);

    webauthn_creds_[cred.credential_id] = cred;
    user_webauthn_[cred.user_id].push_back(cred.credential_id);
    return Result<void>::success();
}

Result<std::vector<WebAuthnCredentialRecord>>
MemoryStorageAdapter::get_webauthn_credentials(const std::string& user_id) {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<WebAuthnCredentialRecord> out;
    auto it = user_webauthn_.find(user_id);
    if (it == user_webauthn_.end())
        return Result<std::vector<WebAuthnCredentialRecord>>::success(out);

    for (const auto& cid : it->second) {
        auto cit = webauthn_creds_.find(cid);
        if (cit != webauthn_creds_.end())
            out.push_back(cit->second);
    }
    return Result<std::vector<WebAuthnCredentialRecord>>::success(std::move(out));
}

Result<WebAuthnCredentialRecord>
MemoryStorageAdapter::get_webauthn_credential(const std::string& credential_id) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = webauthn_creds_.find(credential_id);
    if (it == webauthn_creds_.end())
        return Result<WebAuthnCredentialRecord>::failure(
            "credential not found: " + credential_id);

    return Result<WebAuthnCredentialRecord>::success(it->second);
}

Result<void> MemoryStorageAdapter::update_webauthn_sign_count(
    const std::string& credential_id, uint64_t new_count)
{
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = webauthn_creds_.find(credential_id);
    if (it == webauthn_creds_.end())
        return Result<void>::failure("credential not found: " + credential_id);

    it->second.sign_count = new_count;
    return Result<void>::success();
}

Result<void> MemoryStorageAdapter::remove_webauthn_credential(
    const std::string& credential_id)
{
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = webauthn_creds_.find(credential_id);
    if (it == webauthn_creds_.end())
        return Result<void>::failure("credential not found: " + credential_id);

    // Remove from user's credential list
    auto& user_creds = user_webauthn_[it->second.user_id];
    user_creds.erase(
        std::remove(user_creds.begin(), user_creds.end(), credential_id),
        user_creds.end());

    webauthn_creds_.erase(it);
    return Result<void>::success();
}


// ─── Push devices ────────────────────────────────────────────────────────────

Result<void> MemoryStorageAdapter::add_push_device(const PushDeviceRecord& dev) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (push_devices_.count(dev.device_id))
        return Result<void>::failure("push device already exists: " + dev.device_id);

    push_devices_[dev.device_id] = dev;
    user_push_devs_[dev.user_id].push_back(dev.device_id);
    return Result<void>::success();
}

Result<std::vector<PushDeviceRecord>>
MemoryStorageAdapter::get_push_devices(const std::string& user_id) {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<PushDeviceRecord> out;
    auto it = user_push_devs_.find(user_id);
    if (it == user_push_devs_.end())
        return Result<std::vector<PushDeviceRecord>>::success(out);

    for (const auto& did : it->second) {
        auto dit = push_devices_.find(did);
        if (dit != push_devices_.end() && dit->second.active)
            out.push_back(dit->second);
    }
    return Result<std::vector<PushDeviceRecord>>::success(std::move(out));
}

Result<PushDeviceRecord>
MemoryStorageAdapter::get_push_device(const std::string& device_id) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = push_devices_.find(device_id);
    if (it == push_devices_.end())
        return Result<PushDeviceRecord>::failure(
            "push device not found: " + device_id);

    return Result<PushDeviceRecord>::success(it->second);
}

Result<void> MemoryStorageAdapter::deactivate_push_device(
    const std::string& device_id)
{
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = push_devices_.find(device_id);
    if (it == push_devices_.end())
        return Result<void>::failure("push device not found: " + device_id);

    it->second.active = false;
    return Result<void>::success();
}

} // namespace ezone
