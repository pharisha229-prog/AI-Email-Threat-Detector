from flask import Flask, render_template, request
from werkzeug.exceptions import RequestEntityTooLarge

import pickle
from pathlib import Path

from utils.url_analyzer import analyze_urls
from utils.email_parser import analyze_sender, parse_eml


app = Flask(__name__)


# ==========================================
# UPLOAD LIMIT
# ==========================================

# Maximum upload size = 5 MB

app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024


BASE_DIR = Path(__file__).resolve().parent


# ==========================================
# LOAD ML MODEL
# ==========================================

with open(
    BASE_DIR / "model" / "model.pkl",
    "rb"
) as file:

    model = pickle.load(file)


# ==========================================
# LOAD TF-IDF VECTORIZER
# ==========================================

with open(
    BASE_DIR / "model" / "vectorizer.pkl",
    "rb"
) as file:

    vectorizer = pickle.load(file)


# ==========================================
# HOME PAGE
# ==========================================

@app.route("/")
def home():

    return render_template(
        "index.html"
    )


# ==========================================
# ANALYZE EMAIL
# ==========================================

@app.route(
    "/analyze",
    methods=["POST"]
)
def analyze():

    try:

        # ==========================================
        # GET EMAIL TEXT
        # ==========================================

        email = request.form.get(
            "email",
            ""
        ).strip()


        # ==========================================
        # GET UPLOADED FILE
        # ==========================================

        uploaded_file = request.files.get(
            "email_file"
        )


        extracted_html_links = []


        # ==========================================
        # HANDLE .EML FILE
        # ==========================================

        if (
            uploaded_file
            and uploaded_file.filename
        ):

            filename = uploaded_file.filename.strip()


            # Check file extension

            if not filename.lower().endswith(
                ".eml"
            ):

                return render_template(
                    "index.html",
                    error=(
                        "Invalid file type. "
                        "Please upload an .eml file."
                    )
                )


            try:

                file_content = uploaded_file.read()


                # Check empty file

                if not file_content:

                    return render_template(
                        "index.html",
                        error=(
                            "The uploaded .eml file "
                            "is empty."
                        )
                    )


                # Parse email

                parsed_email = parse_eml(
                    file_content
                )


                # Check whether useful email content exists

                if not any([
                    parsed_email.get("sender"),
                    parsed_email.get("subject"),
                    parsed_email.get("body")
                ]):

                    return render_template(
                        "index.html",
                        error=(
                            "The .eml file does not "
                            "contain readable email content."
                        )
                    )


                # Reconstruct email for analysis

                email = (
                    "From: "
                    + parsed_email["sender"]
                    + "\n"
                    + "Reply-To: "
                    + parsed_email["reply_to"]
                    + "\n"
                    + "Subject: "
                    + parsed_email["subject"]
                    + "\n\n"
                    + parsed_email["body"]
                )


                extracted_html_links = (
                    parsed_email["html_links"]
                )


            except Exception:

                return render_template(
                    "index.html",
                    error=(
                        "Unable to read this .eml file. "
                        "Please check that the file is a "
                        "valid email file."
                    )
                )


        # ==========================================
        # CHECK EMPTY EMAIL
        # ==========================================

        if not email:

            return render_template(
                "index.html",
                error=(
                    "Please paste an email or "
                    "upload a .eml file."
                )
            )


        # ==========================================
        # LIMIT EMAIL TEXT SIZE
        # ==========================================

        if len(email) > 500000:

            return render_template(
                "index.html",
                error=(
                    "The email content is too large "
                    "to analyze. Please use a smaller "
                    "email."
                )
            )


        email_lower = email.lower()

        threats = []


        # ==========================================
        # 1. SENDER ANALYSIS
        # ==========================================

        sender_findings = analyze_sender(
            email
        )

        sender_score = 0


        for finding in sender_findings:

            threats.append(
                finding
            )

            sender_score += 25


        sender_score = min(
            sender_score,
            100
        )


        # ==========================================
        # 2. KEYWORD ANALYSIS
        # ==========================================

        keywords = {

            "urgent": 15,

            "immediately": 15,

            "verify": 15,

            "verification": 15,

            "password": 20,

            "otp": 20,

            "account suspended": 20,

            "account locked": 20,

            "click here": 15,

            "claim": 10,

            "winner": 15,

            "prize": 15,

            "reward": 10,

            "bank": 10,

            "payment": 15,

            "credit card": 15,

            "login": 10,

            "confirm your identity": 20,

            "security alert": 15

        }


        keyword_score = 0


        for word, score in keywords.items():

            if word in email_lower:

                keyword_score += score

                threats.append(
                    "Suspicious keyword: "
                    + word
                )


        keyword_score = min(
            keyword_score,
            100
        )


        # ==========================================
        # 3. URL ANALYSIS
        # ==========================================

        url_findings = analyze_urls(
            email,
            extracted_html_links
        )


        url_score = 0


        if url_findings:

            for finding in url_findings:

                threats.append(
                    finding
                )


            url_score = min(
                len(url_findings) * 30,
                100
            )


        # ==========================================
        # 4. ML ANALYSIS
        # ==========================================

        email_vector = vectorizer.transform(
            [email]
        )


        probability = model.predict_proba(
            email_vector
        )[0]


        threat_index = list(
            model.classes_
        ).index(
            "threat"
        )


        ml_score = int(
            probability[threat_index] * 100
        )


        # ==========================================
        # 5. FINAL RISK SCORE
        # ==========================================

        risk_score = int(

            (ml_score * 0.40)

            +

            (keyword_score * 0.20)

            +

            (url_score * 0.20)

            +

            (sender_score * 0.20)

        )


        # No suspicious indicators
        # = keep result below Medium Risk

        if not threats:

            risk_score = min(
                risk_score,
                29
            )


        risk_score = min(
            max(
                risk_score,
                0
            ),
            100
        )


        # ==========================================
        # 6. RISK LEVEL
        # ==========================================

        if risk_score >= 60:

            result = "High Risk"

        elif risk_score >= 30:

            result = "Medium Risk"

        else:

            result = "Low Risk"


        # ==========================================
        # 7. SECURITY RECOMMENDATION
        # ==========================================

        if risk_score >= 60:

            recommendation = (
                "High risk indicators were detected. "
                "Do not click links or open unexpected "
                "attachments. Do not provide passwords, "
                "OTPs, banking details, or other sensitive "
                "information. Verify the sender through "
                "an official or trusted channel."
            )


        elif url_findings and sender_findings:

            recommendation = (
                "Both the URL and sender information "
                "show suspicious indicators. Avoid "
                "clicking links or replying to the email. "
                "Verify the sender and destination "
                "through a trusted channel."
            )


        elif url_findings:

            recommendation = (
                "A suspicious URL was detected. "
                "Do not click the link until its destination "
                "has been independently verified. "
                "If possible, visit the official website "
                "directly instead of using the email link."
            )


        elif sender_findings:

            recommendation = (
                "The sender information contains "
                "suspicious indicators. Do not reply "
                "with sensitive information. Verify "
                "the sender using a trusted contact "
                "method."
            )


        elif keyword_score >= 40:

            recommendation = (
                "The email contains several suspicious "
                "keywords or requests. Be cautious with "
                "requests involving passwords, OTPs, "
                "payments, account verification, or "
                "urgent actions."
            )


        elif keyword_score > 0:

            recommendation = (
                "Some potentially suspicious language "
                "was detected. Carefully verify the "
                "sender and request before taking action."
            )


        else:

            recommendation = (
                "No major suspicious indicators were "
                "detected by the current analysis. "
                "Still verify unexpected requests before "
                "clicking links, opening attachments, or "
                "sharing sensitive information."
            )


        # ==========================================
        # 8. REMOVE DUPLICATE THREATS
        # ==========================================

        threats = list(
            dict.fromkeys(
                threats
            )
        )


        # ==========================================
        # 9. SEND RESULT TO WEBSITE
        # ==========================================

        return render_template(

            "index.html",

            result=result,

            risk_score=risk_score,

            recommendation=recommendation,

            threats=threats,

            ml_detected=ml_score >= 50,

            keyword_detected=keyword_score > 0,

            url_detected=len(
                url_findings
            ) > 0,

            sender_detected=len(
                sender_findings
            ) > 0

        )


    # ==========================================
    # GENERAL ERROR HANDLING
    # ==========================================

    except Exception:

        return render_template(
            "index.html",
            error=(
                "Something went wrong while "
                "analyzing the email. Please try "
                "again with valid email content."
            )
        )


# ==========================================
# FILE TOO LARGE ERROR
# ==========================================

@app.errorhandler(
    RequestEntityTooLarge
)
def file_too_large(error):

    return render_template(
        "index.html",
        error=(
            "The uploaded file is too large. "
            "Maximum allowed size is 5 MB."
        )
    ), 413


# ==========================================
# START FLASK
# ==========================================

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)