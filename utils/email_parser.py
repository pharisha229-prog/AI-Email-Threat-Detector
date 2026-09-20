from email import policy
from email.parser import BytesParser
from html.parser import HTMLParser
import re


# ==========================================
# HTML LINK EXTRACTOR
# ==========================================

class LinkExtractor(HTMLParser):

    def __init__(self):

        super().__init__()

        self.links = []


    def handle_starttag(
        self,
        tag,
        attrs
    ):

        if tag.lower() == "a":

            for name, value in attrs:

                if (
                    name.lower() == "href"
                    and value
                ):

                    self.links.append(
                        value
                    )


# ==========================================
# PARSE .EML FILE
# ==========================================

def parse_eml(file_content):

    msg = BytesParser(
        policy=policy.default
    ).parsebytes(
        file_content
    )


    sender = msg.get(
        "From",
        ""
    )

    reply_to = msg.get(
        "Reply-To",
        ""
    )

    subject = msg.get(
        "Subject",
        ""
    )


    body_parts = []

    html_links = []


    # ======================================
    # MULTIPART EMAIL
    # ======================================

    if msg.is_multipart():

        for part in msg.walk():

            content_type = (
                part.get_content_type()
            )


            # Plain text
            if content_type == "text/plain":

                try:

                    content = (
                        part.get_content()
                    )

                    if content:

                        body_parts.append(
                            content
                        )

                except Exception:

                    pass


            # HTML
            elif content_type == "text/html":

                try:

                    html_content = (
                        part.get_content()
                    )


                    if html_content:

                        parser = (
                            LinkExtractor()
                        )

                        parser.feed(
                            html_content
                        )


                        html_links.extend(
                            parser.links
                        )


                        body_parts.append(
                            html_content
                        )

                except Exception:

                    pass


    # ======================================
    # NON-MULTIPART EMAIL
    # ======================================

    else:

        try:

            content = msg.get_content()


            if content:

                body_parts.append(
                    content
                )


                if (
                    msg.get_content_type()
                    == "text/html"
                ):

                    parser = (
                        LinkExtractor()
                    )

                    parser.feed(
                        content
                    )


                    html_links.extend(
                        parser.links
                    )

        except Exception:

            pass


    body = "\n".join(
        body_parts
    )


    # Remove duplicate links
    html_links = list(
        dict.fromkeys(
            html_links
        )
    )


    return {

        "sender": sender,

        "reply_to": reply_to,

        "subject": subject,

        "body": body,

        "html_links": html_links
    }


# ==========================================
# SENDER ANALYSIS
# ==========================================

def analyze_sender(email_text):

    findings = []


    # ======================================
    # FIND FROM EMAIL
    # ======================================

    from_match = re.search(

        r"From:\s*(?:.*?<)?"
        r"([\w.+-]+@[\w.-]+\.\w+)",

        email_text,

        re.IGNORECASE
    )


    # ======================================
    # FIND REPLY-TO EMAIL
    # ======================================

    reply_match = re.search(

        r"Reply-To:\s*(?:.*?<)?"
        r"([\w.+-]+@[\w.-]+\.\w+)",

        email_text,

        re.IGNORECASE
    )


    # ======================================
    # FROM vs REPLY-TO
    # ======================================

    if (
        from_match
        and reply_match
    ):

        from_email = (
            from_match.group(1)
            .lower()
        )

        reply_email = (
            reply_match.group(1)
            .lower()
        )


        from_domain = (
            from_email.split("@")[1]
        )

        reply_domain = (
            reply_email.split("@")[1]
        )


        if (
            from_domain
            != reply_domain
        ):

            findings.append(
                "Sender and Reply-To domains do not match"
            )


    # ======================================
    # TEMPORARY EMAIL DOMAINS
    # ======================================

    if from_match:

        from_email = (
            from_match.group(1)
            .lower()
        )


        domain = (
            from_email.split("@")[1]
        )


        temporary_domains = [

            "mailinator.com",

            "tempmail.com",

            "10minutemail.com",

            "guerrillamail.com",

            "maildrop.cc",

            "yopmail.com"

        ]


        if domain in temporary_domains:

            findings.append(
                "Temporary email domain detected"
            )


    # ======================================
    # SUSPICIOUS DOMAIN WORDS
    # ======================================

    if from_match:

        from_email = (
            from_match.group(1)
            .lower()
        )


        domain = (
            from_email.split("@")[1]
        )


        suspicious_domain_words = [

            "secure",

            "verify",

            "support",

            "account",

            "security",

            "login",

            "update"

        ]


        matched_words = []


        for word in suspicious_domain_words:

            if word in domain:

                matched_words.append(
                    word
                )


        if matched_words:

            findings.append(
                "Sender domain contains suspicious terms: "
                + ", ".join(
                    matched_words
                )
            )


    # ======================================
    # DISPLAY NAME VS EMAIL DOMAIN
    # ======================================

    display_match = re.search(

        r"From:\s*([^<\n]+)"
        r"<([\w.+-]+@[\w.-]+\.\w+)>",

        email_text,

        re.IGNORECASE
    )


    if display_match:

        display_name = (
            display_match.group(1)
            .strip()
            .lower()
        )

        sender_email = (
            display_match.group(2)
            .lower()
        )


        sender_domain = (
            sender_email.split("@")[1]
        )


        trusted_names = [

            "paypal",

            "microsoft",

            "google",

            "apple",

            "amazon",

            "bank",

            "netflix"

        ]


        for name in trusted_names:

            if name in display_name:

                if name not in sender_domain:

                    findings.append(
                        "Display name does not match sender domain"
                    )

                    break


    # ======================================
    # MISSING REPLY-TO
    # ======================================

    if (
        from_match
        and not reply_match
    ):

        # This is NOT automatically malicious.
        # We don't flag it as a threat.
        pass


    # Remove duplicates
    return list(
        dict.fromkeys(
            findings
        )
    )