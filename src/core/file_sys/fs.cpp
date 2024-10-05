// SPDX-FileCopyrightText: Copyright 2024 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#include <algorithm>
#include "common/string_util.h"
#include "core/file_sys/fs.h"

namespace Core::FileSys {

constexpr int RESERVED_HANDLES = 3; // First 3 handles are stdin,stdout,stderr

void MntPoints::Mount(const std::filesystem::path& host_folder, const std::string& guest_folder,
                      bool read_only) {
    std::scoped_lock lock{m_mutex};
    m_mnt_pairs.emplace_back(host_folder, guest_folder, read_only);
}

void MntPoints::Unmount(const std::filesystem::path& host_folder, const std::string& guest_folder) {
    std::scoped_lock lock{m_mutex};
    auto it = std::remove_if(m_mnt_pairs.begin(), m_mnt_pairs.end(),
                             [&](const MntPair& pair) { return pair.mount == guest_folder; });
    m_mnt_pairs.erase(it, m_mnt_pairs.end());
}

void MntPoints::UnmountAll() {
    std::scoped_lock lock{m_mutex};
    m_mnt_pairs.clear();
}

std::filesystem::path MntPoints::GetHostPath(std::string_view guest_directory, bool* is_read_only) {
    // Evil games like Turok2 pass double slashes e.g /app0//game.kpf
    std::string corrected_path(guest_directory);
    size_t pos = corrected_path.find("//");
    while (pos != std::string::npos) {
        corrected_path.replace(pos, 2, "/");
        pos = corrected_path.find("//", pos + 1);
    }

    const MntPair* mount = GetMount(corrected_path);
    if (!mount) {
        return "";
    }

    if (is_read_only) {
        *is_read_only = mount->read_only;
    }

    // Nothing to do if getting the mount itself.
    if (corrected_path == mount->mount) {
        return mount->host_path;
    }

    // Remove device (e.g /app0) from path to retrieve relative path.
    pos = mount->mount.size() + 1;
    const auto rel_path = std::string_view(corrected_path).substr(pos);
    const auto host_path = mount->host_path / rel_path;
    if (!NeedsCaseInsensitiveSearch) {
        return host_path;
    }

    // If the path does not exist attempt to verify this.
    // Retrieve parent path until we find one that exists.
    std::scoped_lock lk{m_mutex};
    path_parts.clear();
    auto current_path = host_path;
    while (!std::filesystem::exists(current_path)) {
        // We have probably cached this if it's a folder.
        if (auto it = path_cache.find(current_path); it != path_cache.end()) {
            current_path = it->second;
            break;
        }
        path_parts.emplace_back(current_path.filename());
        current_path = current_path.parent_path();
    }

    // We have found an anchor. Traverse parts we recoded and see if they
    // exist in filesystem but in different case.
    auto guest_path = current_path;
    while (!path_parts.empty()) {
        const auto part = path_parts.back();
        const auto add_match = [&](const auto& host_part) {
            current_path /= host_part;
            guest_path /= part;
            path_cache[guest_path] = current_path;
            path_parts.pop_back();
        };

        // Can happen when the mismatch is in upper folder.
        if (std::filesystem::exists(current_path / part)) {
            add_match(part);
            continue;
        }
        const auto part_low = Common::ToLower(part.string());
        bool found_match = false;
        for (const auto& path : std::filesystem::directory_iterator(current_path)) {
            const auto candidate = path.path().filename();
            const auto filename = Common::ToLower(candidate.string());
            // Check if a filename matches in case insensitive manner.
            if (filename != part_low) {
                continue;
            }
            // We found a match, record the actual path in the cache.
            add_match(candidate);
            found_match = true;
            break;
        }
        if (!found_match) {
            // Opening the guest path will surely fail but at least gives
            // a better error message than the empty path.
            return host_path;
        }
    }

    // The path was found.
    return current_path;
}

int HandleTable::CreateHandle() {
    std::scoped_lock lock{m_mutex};

    auto* file = new File{};
    file->is_directory = false;
    file->is_opened = false;

    int existingFilesNum = m_files.size();

    for (int index = 0; index < existingFilesNum; index++) {
        if (m_files.at(index) == nullptr) {
            m_files[index] = file;
            return index + RESERVED_HANDLES;
        }
    }

    m_files.push_back(file);
    return m_files.size() + RESERVED_HANDLES - 1;
}

void HandleTable::DeleteHandle(int d) {
    std::scoped_lock lock{m_mutex};
    delete m_files.at(d - RESERVED_HANDLES);
    m_files[d - RESERVED_HANDLES] = nullptr;
}

File* HandleTable::GetFile(int d) {
    std::scoped_lock lock{m_mutex};
    return m_files.at(d - RESERVED_HANDLES);
}

File* HandleTable::GetFile(const std::filesystem::path& host_name) {
    for (auto* file : m_files) {
        if (file != nullptr && file->m_host_name == host_name) {
            return file;
        }
    }
    return nullptr;
}

} // namespace Core::FileSys
