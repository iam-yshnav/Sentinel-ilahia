from flask import Flask, render_template, request, redirect, url_for, flash
import os

app = Flask(__name__)
app.secret_key = "your_secret_key"  # Used for flashing success messages
UPLOAD_FOLDER = 'uploads/'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Ensure the upload folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


@app.route('/')
def home():
    return render_template('report.html')

@app.route('/submit-threat', methods=['POST'])
def submit_threat():
    # Extract form data
    threat_title = request.form.get('threat_title')
    summary = request.form.get('summary')
    iocs = request.form.get('iocs', 'None provided')
    affected_platforms = request.form.get('affected_platforms', 'None specified')
    detailed_description = request.form.get('detailed_description')
    impact_type = request.form.get('impact_type')
    severity_level = request.form.get('severity_level')
    mitigation_actions = request.form.get('mitigation_actions', 'No actions taken yet')

    # Handle file upload
    attachment = request.files.get('attachment')
    attachment_path = None
    if attachment and attachment.filename != '':
        attachment_path = os.path.join(app.config['UPLOAD_FOLDER'], attachment.filename)
        attachment.save(attachment_path)

    # Simulate saving data (could connect to a database here)
    print(f"""
    Threat Submission:
    -------------------
    Title: {threat_title}
    Summary: {summary}
    IOCs: {iocs}
    Affected Platforms: {affected_platforms}
    Detailed Description: {detailed_description}
    Impact Type: {impact_type}
    Severity Level: {severity_level}
    Mitigation Actions: {mitigation_actions}
    Attachment: {attachment_path if attachment_path else 'No attachment uploaded'}
    """)

    # Flash a success message
    flash("Threat report submitted successfully!", "success")
    return redirect(url_for('home'))


if __name__ == '__main__':
    app.run(debug=True)
