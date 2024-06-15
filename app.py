from flask import Flask, render_template, request, redirect, url_for, flash, make_response, session, jsonify, send_file, flash
from transformers import BertForTokenClassification, AutoTokenizer
import torch
import re
import pdfkit
import os
import mysql.connector
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS
from datetime import datetime
import io

app = Flask(__name__)
CORS(app)

# A key to encrypt cookies
app.secret_key="MySuperKey"

db_config = {
    'user': 'root',
    'password': '',
    'host': 'localhost',
    'database': 'email_extraction_tool'
}

# Load your trained model and tokenizer
model_path = r'C:\Users\chann\Documents\Z\bert_ner_model'
model = BertForTokenClassification.from_pretrained(model_path)
tokenizer = AutoTokenizer.from_pretrained(model_path)

# Label map (used for converting predictions to labels)
label_map = {
    0: "O",
    1: "B-Message-ID",
    2: "I-Message-ID",
    3: "B-Date",
    4: "I-Date",
    5: "B-From",
    6: "I-From",
    7: "B-To",
    8: "I-To",
    9: "B-Subject",
    10: "I-Subject",
    11: "B-Cc",
    12: "I-Cc",
    13: "B-Mime-Version",
    14: "I-Mime-Version",
    15: "B-Content-Type",
    16: "I-Content-Type",
    17: "B-Content-Transfer-Encoding",
    18: "I-Content-Transfer-Encoding",
    19: "B-Bcc",
    20: "I-Bcc",
    21: "B-X-From",
    22: "I-X-From",
    23: "B-X-To",
    24: "I-X-To",
    25: "B-X-cc",
    26: "I-X-cc",
    27: "B-X-bcc",
    28: "I-X-bcc",
    29: "B-X-Folder",
    30: "I-X-Folder",
    31: "B-X-Origin",
    32: "I-X-Origin",
    33: "B-X-FileName",
    34: "I-X-FileName",
}

@app.route('/')
def index():
    user_email = session.get('email')
    activity_logs = []
    if user_email:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor(dictionary=True)

        try:
            cursor.execute("SELECT filename, timestamp FROM extracted_files WHERE email = %s ORDER BY timestamp DESC", (user_email,))
            activity_logs = cursor.fetchall()
            print("Activity Logs:", activity_logs)  # Debugging: Print fetched data
        except mysql.connector.Error as err:
            flash(f"Error: {err}", 'danger')
        finally:
            cursor.close()
            conn.close()

    return render_template('index.html', activity_logs=activity_logs)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor(dictionary=True)

        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()

        cursor.close()
        conn.close()

        if user:
            print(f"Password in DB: {user['password']}")  # Debugging print statement
            print(f"Password entered: {password}")  # Debugging print statement
            if check_password_hash(user['password'], password):
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['email'] = user['email']
                session['is_admin'] = user['is_admin']
                session['logged_in'] = True
                if user['is_admin']:
                    return redirect(url_for('admin'))
                else:
                    return redirect(url_for('index'))
            else:
                flash('Invalid email or password', 'danger')
        else:
            flash('Invalid email or password', 'danger')
    
    return render_template('login.html')


def is_valid_email(email):
    """Validate email format."""
    email_regex = re.compile(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$')
    return email_regex.match(email) is not None

def is_strong_password(password):
    """Validate password strength."""
    # Password should be at least 8 characters long and include at least one digit, one uppercase letter, and one lowercase letter
    password_regex = re.compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d]{8,}$')
    return password_regex.match(password) is not None

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        is_admin = request.form.get('is_admin', False)

        # Check if email is valid
        if not is_valid_email(email):
            flash('Invalid email address.', 'danger')
            return redirect(request.url)

        # Check if password is strong
        if not is_strong_password(password):
            flash('Password must be at least 8 characters long and include at least one digit, one uppercase letter, and one lowercase letter.', 'danger')
            return redirect(request.url)

        # Check if username or email already exists
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE username = %s OR email = %s", (username, email))
        existing_user = cursor.fetchone()

        if existing_user:
            if existing_user['username'] == username:
                flash('Username already exists. Please choose another one.', 'danger')
            elif existing_user['email'] == email:
                flash('Email already registered. Please use a different email.', 'danger')
            return redirect(request.url)

        hashed_password = generate_password_hash(password)

        try:
            cursor.execute("INSERT INTO users (username, email, password, is_admin) VALUES (%s, %s, %s, %s)",
                           (username, email, hashed_password, is_admin))
            conn.commit()
            flash('Signup successful! Please login.', 'success')
            return redirect(url_for('login'))
        except mysql.connector.Error as err:
            flash(f"Error: {err}", 'danger')
        finally:
            cursor.close()
            conn.close()

    return render_template('signup.html')


@app.route('/admin')
def admin():
    if not session.get('logged_in') or not session.get('is_admin'):
        return redirect(url_for('login'))

    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor(dictionary=True)

    # Fetch total users
    cursor.execute("SELECT COUNT(*) AS total_users FROM users")
    total_users = cursor.fetchone()['total_users']

    # Fetch active users (assuming 'active' means non-admin users for this example)
    cursor.execute("SELECT COUNT(*) AS active_users FROM users WHERE is_admin = 0")
    active_users = cursor.fetchone()['active_users']

    # Fetch total admins
    cursor.execute("SELECT COUNT(*) AS total_admins FROM users WHERE is_admin = 1")
    total_admins = cursor.fetchone()['total_admins']

    # Fetch recent activities from the extracted_files table
    cursor.execute("SELECT email, filename, timestamp FROM extracted_files ORDER BY timestamp DESC LIMIT 10")
    recent_activities = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template('admin.html', total_users=total_users, active_users=active_users, total_admins=total_admins,
                           recent_activities=recent_activities)


@app.route('/admin/manage-users')
def manage_users():
    if not session.get('logged_in') or not session.get('is_admin'):
        return redirect(url_for('index'))
    
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM users")
    users = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template('admin_manage_user.html', users=users)

# Function to create user
@app.route('/admin/create', methods=['POST'])
def admin_create():
    if not session.get('logged_in') or not session.get('is_admin'):
        return jsonify({'success': False, 'message': 'You do not have permission to access this page.'})

    username = request.form['username']
    email = request.form['email']
    password = request.form['password']
    is_admin = request.form.get('is_admin', 0)

    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor()

    try:
        cursor.execute("INSERT INTO users (username, email, password, is_admin) VALUES (%s, %s, %s, %s)",
                       (username, email, password, is_admin))
        conn.commit()
        return jsonify({'success': True, 'message': 'User created successfully!'})
    except mysql.connector.Error as err:
        return jsonify({'success': False, 'message': f"Error: {err}"})
    finally:
        cursor.close()
        conn.close()

# Obtain the user information for display in the update form
@app.route('/get_user/<int:user_id>')
def get_user(user_id):
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor(dictionary=True)  # Use dictionary cursor to fetch results as dictionary
    try:
        cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
        user = cursor.fetchone()
        if user:
            return jsonify(user)
        else:
            return jsonify({'error': 'User not found'})
    except mysql.connector.Error as err:
        return jsonify({'error': str(err)})
    finally:
        cursor.close()
        conn.close()

# Function to update user information
@app.route('/admin/update/<int:user_id>', methods=['POST'])
def admin_update(user_id):
    if not session.get('logged_in') or not session.get('is_admin'):
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('index'))

    username = request.form['username']
    email = request.form['email']
    password = request.form['password']
    is_admin = request.form.get('is_admin', 0)

    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor()

    try:
        if password:
            password = generate_password_hash(password, method='pbkdf2:sha256')  # Correct the hashing method
            cursor.execute("UPDATE users SET username = %s, email = %s, password = %s, is_admin = %s WHERE id = %s",
                           (username, email, password, is_admin, user_id))
        else:
            cursor.execute("UPDATE users SET username = %s, email = %s, is_admin = %s WHERE id = %s",
                           (username, email, is_admin, user_id))

        conn.commit()

        # Fetch the updated user details
        cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
        updated_user = cursor.fetchone()

        if updated_user:
            return jsonify({'success': True, 'message': 'User updated successfully!'})
        else:
            return jsonify({'success': False, 'message': 'Failed to fetch updated user data.'})
    except mysql.connector.Error as err:
        return jsonify({'success': False, 'message': str(err)})
    finally:
        cursor.close()
        conn.close()

@app.route('/admin/delete/<int:user_id>', methods=['POST'])
def admin_delete(user_id):
    if not session.get('logged_in') or not session.get('is_admin'):
        flash('You do not have permission to access this page.', 'danger')
        return jsonify({'success': False, 'message': 'You do not have permission to access this page.'})

    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor()

    try:
        cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
        conn.commit()
        return jsonify({'success': True, 'message': 'User deleted successfully!'})
    except mysql.connector.Error as err:
        return jsonify({'success': False, 'message': f"Error: {err}"})
    finally:
        cursor.close()
        conn.close()

@app.route('/admin/report')
def report():
    if not session.get('logged_in') or not session.get('is_admin'):
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('index'))

    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT email, filename, timestamp FROM extracted_files")
    reports = cursor.fetchall()

    cursor.close()
    conn.close()
    return render_template('admin_report.html', reports=reports)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

path_to_wkhtmltopdf = r'C:\Program Files\wkhtmltopdf\bin\wkhtmltopdf.exe'
config = pdfkit.configuration(wkhtmltopdf=path_to_wkhtmltopdf)

# Allowed extensions for file upload
ALLOWED_EXTENSIONS = {'txt', 'eml'}

# Set the upload folder path
UPLOAD_FOLDER = os.path.join(app.root_path, 'uploads')
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/extract', methods=['POST'])
def extract():
    user_email = session.get('email')
    if 'file' not in request.files and 'email' not in request.form:
        flash('No file or email content provided!', 'danger')
        return redirect(request.url)

    email_content = request.form.get('email', '')
    file = request.files.get('file')
    base_filename = "text"

    if file and allowed_file(file.filename):
        base_filename = secure_filename(file.filename).rsplit('.', 1)[0]  # Strip the original extension
        filename = f"{base_filename}.pdf"
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(file.filename))
        print(f"Saving file to: {file_path}")  # Debugging print statement
        file.save(file_path)
        with open(file_path, 'r') as f:
            email_content = f.read()

    # Determine the next increment for the file name
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT COUNT(*) AS file_count FROM extracted_files WHERE email = %s AND filename LIKE %s", (user_email, f"{base_filename}(%).pdf"))
        result = cursor.fetchone()
        file_count = result['file_count'] if result else 0
        filename = f"{base_filename}({file_count + 1}).pdf"
    except mysql.connector.Error as err:
        flash(f"Error: {err}", 'danger')
        return redirect(url_for('index'))
    finally:
        cursor.close()
        conn.close()

    entities_to_extract = request.form.getlist('entities')
    extracted_data = extract_headers(email_content, entities_to_extract)

    # Debug: Print values to check if they are correctly retrieved
    print(f"User Email from session: {user_email}")
    print(f"Filename: {filename}")

    pdf_response = generate_pdf(email_content, extracted_data, filename)
    save_pdf_to_db(user_email, filename, pdf_response.data)

    # Save the PDF temporarily
    temp_pdf_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    with open(temp_pdf_path, 'wb') as f:
        f.write(pdf_response.data)

    flash('Headers extracted successfully!', 'success')
    return jsonify({'pdf_url': url_for('serve_pdf', filename=filename)})

def extract_headers(email_content, entities_to_extract):
    tokenized_inputs = tokenizer(email_content, return_offsets_mapping=True, return_tensors="pt", truncation=True, max_length=512)
    input_ids = tokenized_inputs['input_ids']
    attention_mask = tokenized_inputs['attention_mask']
    offsets = tokenized_inputs['offset_mapping'][0]

    with torch.no_grad():
        outputs = model(input_ids=input_ids, attention_mask=attention_mask)

    predictions = torch.argmax(outputs.logits, dim=2)
    spans = []
    current_entity = None
    current_span = []
    span_start = None

    for prediction, offset in zip(predictions[0].numpy(), offsets.numpy()):
        label_id = prediction.item()
        label = label_map[label_id]
        entity_type = label[2:] if label != "O" else None

        if label.startswith("B-") and entity_type in entities_to_extract:
            if current_entity:
                spans.append({
                    "start": span_start, 
                    "end": current_span[-1][1], 
                    "label": current_entity,
                    "text": email_content[span_start:current_span[-1][1]]
                })

            current_entity = entity_type
            current_span = [offset]
            span_start = offset[0]

        elif label.startswith("I-") and entity_type == current_entity:
            current_span.append(offset)
        else:
            if current_entity:
                spans.append({
                    "start": span_start, 
                    "end": current_span[-1][1], 
                    "label": current_entity,
                    "text": email_content[span_start:current_span[-1][1]]
                })
                current_entity = None
                current_span = []
                span_start = None

    if current_entity:
        spans.append({
            "start": span_start, 
            "end": current_span[-1][1], 
            "label": current_entity,
            "text": email_content[span_start:current_span[-1][1]]
        })

    return spans

def generate_pdf(email_content, extracted_data, filename):
    highlighted_text = email_content
    for span in sorted(extracted_data, key=lambda x: x['start'], reverse=True):
        start, end, label, text = span["start"], span["end"], span["label"], span["text"]
        highlighted_text = (
            highlighted_text[:start] +
            f'<mark class="mark {label}">' +
            highlighted_text[start:end] +
            "</mark>" +
            highlighted_text[end:]
        )

    # Use <pre> tag to maintain the text formatting
    html = render_template('results.html', highlighted_text=f"<pre>{highlighted_text}</pre>")

    options = {'enable-local-file-access': None}
    pdf = pdfkit.from_string(html, False, configuration=config, options=options)

    response = make_response(pdf)
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f'inline; filename={filename}'

    return response

def save_pdf_to_db(user_email, filename, pdf_data):
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor()

    try:
        cursor.execute("INSERT INTO extracted_files (email, filename, pdf_data, timestamp) VALUES (%s, %s, %s, %s)", 
                       (user_email, filename, pdf_data, datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
        conn.commit()
        cursor.execute("INSERT INTO activity_log (email, file, timestamp) VALUES (%s, %s, %s)", 
                       (user_email, filename, datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
        conn.commit()
    except mysql.connector.Error as err:
        flash(f"Error: {err}", 'danger')
    finally:
        cursor.close()
        conn.close()

@app.route('/serve_pdf/<filename>')
def serve_pdf(filename):
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if os.path.exists(file_path):
        return send_file(file_path, mimetype='application/pdf')
    else:
        flash('File not found or access denied.', 'danger')
        return redirect(url_for('index'))

@app.route('/download/<filename>', methods=['GET'])
def download_file(filename):
    print(f"Requested filename: {filename}")  # Debugging statement
    user_email = session.get('email')
    if not user_email:
        flash('You need to log in to download files.', 'danger')
        return redirect(url_for('login'))

    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor()

    try:
        cursor.execute("SELECT pdf_data FROM extracted_files WHERE email = %s AND filename = %s", (user_email, filename))
        result = cursor.fetchone()
        if result:
            pdf_data = result[0]
            return send_file(io.BytesIO(pdf_data), mimetype='application/pdf', download_name=filename, as_attachment=True)
        else:
            flash('File not found or access denied.', 'danger')
            return redirect(url_for('index'))
    except mysql.connector.Error as err:
        flash(f"Error: {err}", 'danger')
        return redirect(url_for('index'))
    finally:
        cursor.close()
        conn.close()

@app.route('/delete/<filename>', methods=['POST'])
def delete_file(filename):
    user_email = session.get('email')
    if not user_email:
        flash('You need to log in to delete files.', 'danger')
        return redirect(url_for('login'))

    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor()

    try:
        cursor.execute("DELETE FROM extracted_files WHERE email = %s AND filename = %s", (user_email, filename))
        conn.commit()
        if cursor.rowcount > 0:
            cursor.execute("DELETE FROM activity_log WHERE email = %s AND file = %s", (user_email, filename))
            conn.commit()
            flash('File deleted successfully.', 'success')
            return jsonify({'success': True, 'message': 'File deleted successfully'})
        else:
            flash('File not found or access denied.', 'danger')
            return jsonify({'success': False, 'message': 'File not found or access denied'})
    except mysql.connector.Error as err:
        flash(f"Error: {err}", 'danger')
        return jsonify({'success': False, 'message': str(err)})
    finally:
        cursor.close()
        conn.close()

if __name__ == '__main__':
    app.run(debug=True)
