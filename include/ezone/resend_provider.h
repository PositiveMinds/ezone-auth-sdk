#pragma once

#include "ezone/email_provider.h"
#include <string>

namespace ezone {

struct ResendConfig {
    std::string api_key;              // Resend API key  (re_xxxxxxxxxxxx)
    std::string from;                 // From address    (e.g. "ezone <auth@yourapp.com>")
    std::string register_subject  = "Complete your registration";
    std::string login_subject     = "Your sign-in link";
    std::string reset_subject     = "Reset your account";
    std::string add_device_subject= "Approve new device";
};

class ResendEmailProvider : public EmailProvider {
public:
    explicit ResendEmailProvider(ResendConfig cfg);
    Result<void> send(const MagicLinkEmail& mail) override;

private:
    ResendConfig cfg_;

    std::string subject_for(const std::string& purpose) const;
    std::string build_html(const std::string& link, const std::string& purpose) const;
    std::string build_text(const std::string& link, const std::string& purpose) const;
    std::string build_link(const MagicLinkEmail& mail) const;
};

} // namespace ezone
