#include "ezone/resend_provider.h"

// cpp-httplib with OpenSSL for HTTPS support
#define CPPHTTPLIB_OPENSSL_SUPPORT
#include <httplib.h>

#include <sstream>

namespace ezone {

// ── JSON escape helper (avoids pulling in a full JSON lib) ────────────────────

static std::string json_escape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (unsigned char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (c < 0x20) {
                    char buf[8];
                    snprintf(buf, sizeof(buf), "\\u%04x", c);
                    out += buf;
                } else {
                    out += static_cast<char>(c);
                }
        }
    }
    return out;
}

// ── ResendEmailProvider ───────────────────────────────────────────────────────

ResendEmailProvider::ResendEmailProvider(ResendConfig cfg)
    : cfg_(std::move(cfg)) {}

std::string ResendEmailProvider::subject_for(const std::string& purpose) const {
    if (purpose == "register")   return cfg_.register_subject;
    if (purpose == "reset")      return cfg_.reset_subject;
    if (purpose == "add_device") return cfg_.add_device_subject;
    return cfg_.login_subject;
}

std::string ResendEmailProvider::build_link(const MagicLinkEmail& mail) const {
    std::string path;
    if      (mail.purpose == "register")   path = "/register/complete";
    else if (mail.purpose == "reset")      path = "/reset/complete";
    else if (mail.purpose == "add_device") path = "/devices/add/complete";
    else                                   path = "/auth/complete";

    // URL-encode the token (it's base64url so only = needs encoding, but
    // since we strip padding it's already URL-safe)
    return mail.app_url + path + "?token=" + mail.magic_token;
}

std::string ResendEmailProvider::build_html(const std::string& link,
                                             const std::string& purpose) const {
    std::string action;
    if      (purpose == "register")   action = "complete your registration";
    else if (purpose == "reset")      action = "reset your account";
    else if (purpose == "add_device") action = "approve your new device";
    else                              action = "sign in";

    std::ostringstream html;
    html << R"(<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ezone magic link</title></head>
<body style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
             background:#f8fafc;margin:0;padding:40px 20px;">
  <div style="max-width:480px;margin:0 auto;background:#fff;
              border-radius:12px;padding:40px;border:1px solid #e2e8f0;">
    <div style="text-align:center;margin-bottom:32px;">
      <span style="font-size:2rem;">⚡</span>
      <h1 style="margin:8px 0 0;font-size:1.5rem;color:#0f172a;">ezone</h1>
    </div>
    <p style="color:#334155;font-size:1rem;line-height:1.6;margin:0 0 24px;">
      Click the button below to )" << action << R"(. This link expires in 15 minutes
      and can only be used once.
    </p>
    <div style="text-align:center;margin:32px 0;">
      <a href=")" << json_escape(link) << R"("
         style="background:linear-gradient(135deg,#38bdf8,#0ea5e9);
                color:#0f172a;font-weight:700;font-size:1rem;
                padding:14px 32px;border-radius:8px;
                text-decoration:none;display:inline-block;">
        Click to )" << action << R"(
      </a>
    </div>
    <p style="color:#94a3b8;font-size:0.8rem;text-align:center;margin:0;">
      If you didn't request this, you can safely ignore this email.<br>
      This link will expire automatically.
    </p>
  </div>
</body>
</html>)";
    return html.str();
}

std::string ResendEmailProvider::build_text(const std::string& link,
                                             const std::string& purpose) const {
    std::string action;
    if      (purpose == "register")   action = "complete your registration";
    else if (purpose == "reset")      action = "reset your account";
    else if (purpose == "add_device") action = "approve your new device";
    else                              action = "sign in";

    return "Click the link below to " + action + " (expires in 15 minutes):\n\n"
           + link + "\n\n"
           "If you didn't request this, ignore this email.\n";
}

Result<void> ResendEmailProvider::send(const MagicLinkEmail& mail) {
    const std::string link    = build_link(mail);
    const std::string subject = subject_for(mail.purpose);
    const std::string html    = build_html(link, mail.purpose);
    const std::string text    = build_text(link, mail.purpose);

    // Build JSON payload
    std::string body = "{"
        "\"from\":\""    + json_escape(cfg_.from)    + "\","
        "\"to\":[\""     + json_escape(mail.to)      + "\"],"
        "\"subject\":\"" + json_escape(subject)      + "\","
        "\"html\":\""    + json_escape(html)          + "\","
        "\"text\":\""    + json_escape(text)          + "\""
        "}";

    // POST to Resend API over HTTPS
    httplib::SSLClient client("api.resend.com");
    client.set_connection_timeout(10);
    client.set_read_timeout(15);

    httplib::Headers headers = {
        { "Authorization", "Bearer " + cfg_.api_key },
        { "Content-Type",  "application/json"        },
    };

    auto resp = client.Post("/emails", headers, body, "application/json");

    if (!resp) {
        return Result<void>::failure(
            "Resend: network error — " + httplib::to_string(resp.error()));
    }

    if (resp->status < 200 || resp->status >= 300) {
        return Result<void>::failure(
            "Resend: HTTP " + std::to_string(resp->status)
            + " — " + resp->body);
    }

    return Result<void>::success();
}

} // namespace ezone
