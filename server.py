import os
import signal
import sys
from flask import Flask, request, jsonify, send_from_directory
from datetime import datetime
from threading import Event
from werkzeug.serving import make_server

UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app = Flask(__name__)

shutdown_event = Event()

@app.route('/upload', methods=['POST'])
def upload():
    if 'file' not in request.files:
        return jsonify({"error": "No file part in the request"}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400

    save_path = os.path.join(UPLOAD_FOLDER, file.filename)
    try:
        file.save(save_path)
    except Exception as e:
        app.logger.error(f"Failed to save file {file.filename}: {e}")
        return jsonify({"error": "Failed to save file"}), 500

    app.logger.info(f"{datetime.now()} - Received file saved to: {save_path}")
    return jsonify({"status": "success", "filename": file.filename}), 200

@app.route('/files', methods=['GET'])
def list_files():
    try:
        files = os.listdir(UPLOAD_FOLDER)
        return jsonify({"files": files})
    except Exception as e:
        app.logger.error(f"Failed to list files: {e}")
        return jsonify({"error": "Failed to list files"}), 500

@app.route('/download/<filename>', methods=['GET'])
def download_file(filename):
    try:
        return send_from_directory(UPLOAD_FOLDER, filename, as_attachment=True)
    except Exception as e:
        app.logger.error(f"Failed to send file {filename}: {e}")
        return jsonify({"error": "File not found"}), 404


class ServerThread:
    def __init__(self, app, host='0.0.0.0', port=8000):
        self.server = make_server(host, port, app, threaded=True)
        self.ctx = app.app_context()
        self.ctx.push()

    def start(self):
        app.logger.info(f"Starting server on {self.server.server_address}")
        self.server.serve_forever()

    def shutdown(self):
        app.logger.info("Shutting down server...")
        self.server.shutdown()


def signal_handler(sig, frame):
    app.logger.info('SIGINT received, shutting down...')
    shutdown_event.set()
    server_thread.shutdown()


if __name__ == '__main__':
    import logging

    logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname)s in %(module)s: %(message)s')

    server_thread = ServerThread(app)
    signal.signal(signal.SIGINT, signal_handler)
    try:
        server_thread.start()
    except KeyboardInterrupt:
        pass
    finally:
        app.logger.info("Server stopped cleanly.")
        sys.exit(0)

