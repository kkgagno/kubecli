import http.server
import socketserver
import os

PORT = 8000
DIRECTORY = os.path.join(os.path.expanduser("~"), "ansible_goss_compliance/compliance_html_reports")

class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DIRECTORY, **kwargs)

with socketserver.TCPServer(("0.0.0.0", PORT), Handler) as httpd:
    print("serving at port", PORT)
    httpd.serve_forever()
