import re
from urllib.parse import urlparse


def analyze_urls(text, extra_urls=None):

    # ==========================================
    # FIND URLs FROM EMAIL TEXT
    # ==========================================

    urls = re.findall(
        r"https?://[^\s\"'<>]+",
        text
    )

    # Add links extracted from HTML
    if extra_urls:
        urls.extend(extra_urls)

    # Remove duplicate URLs
    urls = list(
        dict.fromkeys(urls)
    )

    findings = []


    # ==========================================
    # ANALYZE EACH URL
    # ==========================================

    for url in urls:

        clean_url = url.rstrip(
            ".,!?);]"
        )

        parsed = urlparse(
            clean_url
        )

        hostname = parsed.hostname

        if not hostname:
            continue

        hostname_lower = hostname.lower()


        # ======================================
        # 1. IP ADDRESS
        # ======================================

        if re.match(
            r"^\d{1,3}(\.\d{1,3}){3}$",
            hostname
        ):

            findings.append(
                "URL uses an IP address"
            )


        # ======================================
        # 2. URL SHORTENER
        # ======================================

        shorteners = [

            "bit.ly",
            "tinyurl.com",
            "t.co",
            "goo.gl",
            "is.gd",
            "ow.ly",
            "buff.ly",
            "cutt.ly"

        ]

        if hostname_lower in shorteners:

            findings.append(
                "Shortened URL detected"
            )


        # ======================================
        # 3. @ SYMBOL
        # ======================================

        if "@" in clean_url:

            findings.append(
                "URL contains @ symbol"
            )


        # ======================================
        # 4. VERY LONG URL
        # ======================================

        if len(clean_url) > 100:

            findings.append(
                "Unusually long URL"
            )


        # ======================================
        # 5. HTTP WITHOUT HTTPS
        # ======================================

        if parsed.scheme.lower() == "http":

            findings.append(
                "URL does not use HTTPS"
            )


        # ======================================
        # 6. PUNYCODE DOMAIN
        # ======================================

        if hostname_lower.startswith(
            "xn--"
        ) or ".xn--" in hostname_lower:

            findings.append(
                "Potentially deceptive punycode domain"
            )


        # ======================================
        # 7. TOO MANY SUBDOMAINS
        # ======================================

        domain_parts = hostname_lower.split(".")

        if len(domain_parts) >= 5:

            findings.append(
                "URL contains many subdomains"
            )


        # ======================================
        # 8. SUSPICIOUS URL WORDS
        # ======================================

        suspicious_words = [

            "login",
            "verify",
            "verification",
            "secure",
            "account",
            "password",
            "signin",
            "confirm",
            "update",
            "unlock",
            "suspend"

        ]

        path_and_query = (

            (parsed.path or "")
            + " "
            + (parsed.query or "")

        ).lower()


        matched_words = []

        for word in suspicious_words:

            if word in path_and_query:

                matched_words.append(
                    word
                )


        if matched_words:

            findings.append(
                "URL contains suspicious terms: "
                + ", ".join(
                    matched_words
                )
            )


        # ======================================
        # 9. URL USERNAME
        # ======================================

        if parsed.username:

            findings.append(
                "URL contains embedded username information"
            )


    # ==========================================
    # REMOVE DUPLICATE FINDINGS
    # ==========================================

    return list(
        dict.fromkeys(
            findings
        )
    )