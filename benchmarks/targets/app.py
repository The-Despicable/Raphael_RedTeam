from flask import Flask, request

app = Flask(__name__)

@app.route('/')
def index():
    file = request.args.get('file', 'index.html')
    # Vulnerable to LFI (e.g., ?file=../../../../home/opuser/.ssh/id_rsa)
    try:
        # Restricting to local context but allowing traversal
        if '..' in file or '/' in file:
            with open(file, 'r') as f:
                return f.read(), 200, {'Content-Type': 'text/plain'}
        return "Welcome! Try reading a file using ?file=", 200
    except Exception as e:
        return str(e), 404

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
