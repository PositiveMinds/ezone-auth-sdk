#include "ezone/email_provider.h"
#include <iostream>

namespace ezone {

Result<void> LogEmailProvider::send(const MagicLinkEmail& mail) {
    // Build the link URL the same way ResendEmailProvider does
    std::string path;
    if      (mail.purpose == "register")   path = "/register/complete";
    else if (mail.purpose == "reset")      path = "/reset/complete";
    else if (mail.purpose == "add_device") path = "/devices/add/complete";
    else                                   path = "/auth/complete";

    std::string link = mail.app_url + path + "?token=" + mail.magic_token;

    std::cout << "\n"
              << "┌─────────────────────────────────────────────────────┐\n"
              << "│  ezone magic link  [DEV — not sent via email]       │\n"
              << "├─────────────────────────────────────────────────────┤\n"
              << "│  To      : " << mail.to      << "\n"
              << "│  Purpose : " << mail.purpose << "\n"
              << "│  Link    : " << link          << "\n"
              << "└─────────────────────────────────────────────────────┘\n"
              << std::endl;

    return Result<void>::success();
}

} // namespace ezone
