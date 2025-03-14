import os
import re
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from docx import Document
import PyPDF2
import pandas as pd
from flask import Flask, render_template, request, redirect, url_for
import threading

app = Flask(__name__)

BASE_DIR = r"C:\Users\WASIKE BLESSED\Desktop\DLDS\src"
MONITOR_DIR = r"C:\Users\WASIKE BLESSED\Desktop\DLDS\monitored_folder"
UPLOAD_FOLDER = r"C:\Users\WASIKE BLESSED\Desktop\DLDS\uploads"
LOG_FILE = r"C:\Users\WASIKE BLESSED\Desktop\DLDS\logs\leak_log.txt"

for directory in [MONITOR_DIR, UPLOAD_FOLDER, os.path.dirname(LOG_FILE)]:
    if not os.path.exists(directory):
        os.makedirs(directory)

CC_PATTERN = r"\b(?:\d[ -]*?){13,16}\b"
detected_leaks = []

class FileWatcher(FileSystemEventHandler):
    def on_modified(self, event):
        if not event.is_directory:
            self.check_file(event.src_path)

    def on_created(self, event):
        if not event.is_directory:
            self.check_file(event.src_path)

    def check_file(self, filepath):
        if os.path.getsize(filepath) > 10 * 1024 * 1024:
            print(f"Skipping large file: {filepath}")
            return
        try:
            content = self._extract_content(filepath)
            if content and re.search(CC_PATTERN, content):
                print(f"ALERT: Sensitive data found in {filepath}")
                self.log_leak(filepath, "Credit card number detected")
                detected_leaks.append((time.ctime(), filepath, "Credit card number detected"))
        except Exception as e:
            print(f"Error reading {filepath}: {e}")

    def _extract_content(self, filepath):
        if filepath.endswith('.txt'):
            with open(filepath, 'r', encoding='utf-8') as f:
                return f.read()
        elif filepath.endswith('.docx'):
            doc = Document(filepath)
            return "\n".join([para.text for para in doc.paragraphs])
        elif filepath.endswith('.pdf'):
            with open(filepath, 'rb') as f:
                pdf = PyPDF2.PdfReader(f)
                return "\n".join([page.extract_text() for page in pdf.pages])
        elif filepath.endswith('.csv'):
            df = pd.read_csv(filepath)
            return df.to_string()
        return ""

    def log_leak(self, filepath, reason):
        with open(LOG_FILE, "a") as log:
            log.write(f"{time.ctime()} - {filepath} - {reason}\n")

def start_monitoring(directory):
    event_handler = FileWatcher()
    observer = Observer()
    observer.schedule(event_handler, directory, recursive=True)
    observer.start()
    print(f"Monitoring {directory} for data leaks...")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        print("Monitoring stopped.")
    observer.join()

def analyze_file(filepath):
    try:
        content = _extract_content(filepath)
        matches = re.findall(CC_PATTERN, content)
        total_words = len(content.split()) if content else 1
        sensitive_words = sum(len(match.split()) for match in matches)
        percentage = (sensitive_words / total_words) * 100 if total_words > 0 else 0
        print(f"Analyzing {filepath}: {len(matches)} matches found, {percentage:.2f}% leakage")
        return {
            'filename': os.path.basename(filepath),
            'matches': matches,
            'percentage': round(percentage, 2)
        }
    except Exception as e:
        print(f"Error analyzing {filepath}: {e}")
        return {'filename': os.path.basename(filepath), 'matches': [], 'percentage': 0}

def _extract_content(filepath):
    return FileWatcher()._extract_content(filepath)

@app.route('/')
def dashboard():
    return render_template('dashboard.html', leaks=detected_leaks)

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return redirect(url_for('dashboard'))
    file = request.files['file']
    if file.filename == '':
        return redirect(url_for('dashboard'))

    filepath = os.path.join(UPLOAD_FOLDER, file.filename)
    print(f"Saving uploaded file to: {filepath}")
    file.save(filepath)
    result = analyze_file(filepath)
    print(f"Upload analysis result: {result}")
    os.remove(filepath)
    return render_template('dashboard.html', leaks=detected_leaks, result=result)

if __name__ == "__main__":
    monitor_thread = threading.Thread(target=start_monitoring, args=(MONITOR_DIR,))
    monitor_thread.daemon = True
    monitor_thread.start()
    app.run(debug=True, use_reloader=False)