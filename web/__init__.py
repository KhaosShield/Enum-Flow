"""web — browser dashboard and HTML report for EnumFlow."""

import queue
import threading
import webbrowser
import json
import os
import time
from datetime import datetime
from pathlib import Path

from rich.console import Console

try:
    from flask import Flask, Response
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False

_HERE = Path(__file__).parent   # web/ directory for HTML file lookup
_config = None
_sse_queues = []
_sse_lock = threading.Lock()
_phase_has_finding = False
_current_phase_name = ''
_scan_complete_data = None
console = Console()


def init(config_obj):
    """Bind the module to the global Config instance."""
    global _config
    _config = config_obj


def emit_event(event_type, data):
    """Broadcast an SSE event to all connected dashboard clients."""
    global _phase_has_finding, _current_phase_name, _scan_complete_data

    if not _config.dashboard_enabled:
        return

    if event_type == 'phase_start':
        _phase_has_finding = False
        _current_phase_name = data.get('phase', '')

    elif event_type == 'finding':
        if not data.get('null_result', False):
            _phase_has_finding = True

    elif event_type == 'phase_complete':
        if not data.get('skipped', False) and not _phase_has_finding:
            # Auto-inject null-result finding before phase_complete reaches clients
            _null = json.dumps({'type': 'finding', 'data': {
                'section': _current_phase_name,
                'content': 'No findings \u2014 phase completed cleanly.',
                'null_result': True,
            }})
            with _sse_lock:
                for q in _sse_queues:
                    try:
                        q.put_nowait(_null)
                    except Exception:
                        pass
        _phase_has_finding = False
        _current_phase_name = ''

    elif event_type == 'scan_complete':
        _scan_complete_data = data

    payload = json.dumps({'type': event_type, 'data': data})
    with _sse_lock:
        dead = []
        for q in _sse_queues:
            try:
                q.put_nowait(payload)
            except Exception:
                dead.append(q)
        for q in dead:
            _sse_queues.remove(q)


def start_dashboard(open_browser=True):
    """Start the Flask live-dashboard in a background thread."""
    if not FLASK_AVAILABLE:
        console.print("[yellow]⚠ Flask not installed — browser dashboard disabled.[/yellow]")
        console.print("[yellow]  Install with: pip3 install flask[/yellow]")
        return

    import logging
    logging.getLogger('werkzeug').setLevel(logging.ERROR)

    app = Flask(__name__)

    @app.route('/')
    def index():
        return Response((_HERE / 'dashboard.html').read_text(encoding='utf-8'), mimetype='text/html')

    @app.route('/stream')
    def stream():
        def generate():
            client_q = queue.Queue()
            init_payload = json.dumps({
                'type': 'init',
                'data': {
                    'target': _config.target_ip,
                    'elapsed_s': int((datetime.now() - _config.start_time).total_seconds()),
                }
            })
            yield f'data: {init_payload}\n\n'
            if _scan_complete_data is not None:
                sc_payload = json.dumps({'type': 'scan_complete', 'data': _scan_complete_data})
                yield f'data: {sc_payload}\n\n'
            with _sse_lock:
                _sse_queues.append(client_q)
            try:
                while True:
                    try:
                        msg = client_q.get(timeout=25)
                        yield f'data: {msg}\n\n'
                    except queue.Empty:
                        yield ':keepalive\n\n'
            finally:
                with _sse_lock:
                    try:
                        _sse_queues.remove(client_q)
                    except ValueError:
                        pass
        return Response(
            generate(),
            mimetype='text/event-stream',
            headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'},
        )

    @app.route('/report')
    def report():
        if not _config.output_dir:
            return Response('<h1>Report not yet available</h1>', mimetype='text/html', status=404)
        path = os.path.join(_config.output_dir, 'enumeration_report.html')
        if os.path.exists(path):
            with open(path, encoding='utf-8') as f:
                return Response(f.read(), mimetype='text/html')
        return Response(
            '<body style="background:#0d1117;color:#e6edf3;font-family:monospace;padding:40px">'
            '<h2>Report not yet generated</h2><p>Check back when the scan completes.</p></body>',
            mimetype='text/html', status=404,
        )

    def _run():
        try:
            app.run(host='127.0.0.1', port=5000, threaded=True, use_reloader=False)
        except OSError:
            console.print("[yellow]⚠ Port 5000 in use — dashboard unavailable[/yellow]")

    t = threading.Thread(target=_run, daemon=True)
    t.start()

    if open_browser:
        time.sleep(0.5)
        try:
            webbrowser.open('http://127.0.0.1:5000')
        except Exception:
            pass

    _config.dashboard_enabled = True
    console.print("[green]✓[/green] Dashboard: [cyan]http://127.0.0.1:5000[/cyan]")


def generate_html_report():
    """Generate a self-contained HTML report from collected findings."""
    duration = str(datetime.now() - _config.start_time).split('.')[0]

    # Parse markdown_report list into titled sections
    full_md = ''.join(_config.markdown_report)
    accordion_html = ''
    for i, block in enumerate(full_md.split('\n## ')):
        if not block.strip():
            continue
        parts = block.split('\n', 1)
        title = parts[0].strip()
        body = parts[1] if len(parts) > 1 else ''
        esc_body = body.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
        open_cls = ' open' if i < 3 else ''
        tog_icon = '&#9650;' if i < 3 else '&#9660;'
        accordion_html += (
            f'<div class="acc-item">'
            f'<div class="acc-hdr" onclick="tog(this)">'
            f'<div class="acc-dot"></div>'
            f'<div class="acc-title">{title}</div>'
            f'<div class="acc-tog">{tog_icon}</div>'
            f'</div>'
            f'<div class="acc-body{open_cls}"><pre>{esc_body}</pre></div>'
            f'</div>\n'
        )

    # Ports table
    port_rows_html = ''
    for port, info in sorted(_config.discovered_ports.items(),
                              key=lambda x: int(x[0]) if x[0].isdigit() else 9999):
        svc = info.get('service', '-')
        ver = (info.get('version') or '-').replace('<', '&lt;').replace('>', '&gt;')
        port_rows_html += f'<tr><td>{port}</td><td>{svc}</td><td>{ver}</td></tr>\n'

    # Commands log
    cmd_rows_html = ''
    for entry in _config.commands_run:
        ts = entry.get('timestamp', '')
        desc = entry.get('description', '').replace('<', '&lt;').replace('>', '&gt;')
        cmd = entry.get('command', '').replace('<', '&lt;').replace('>', '&gt;')
        cmd_rows_html += f'<tr><td>{ts}</td><td>{desc}</td><td><code>{cmd}</code></td></tr>\n'

    html = (_HERE / 'report.html').read_text(encoding='utf-8')
    html = html.replace('{{TARGET}}', _config.target_ip or 'Unknown')
    html = html.replace('{{DATE}}', _config.start_time.strftime('%Y-%m-%d %H:%M'))
    html = html.replace('{{DURATION}}', duration)
    html = html.replace('{{PORT_COUNT}}', str(len(_config.discovered_ports)))
    html = html.replace('{{HOST_COUNT}}', str(len(_config.discovered_hosts)))
    html = html.replace('{{CMD_COUNT}}', str(len(_config.commands_run)))
    html = html.replace('{{HOSTNAMES}}', ', '.join(_config.discovered_hosts) or 'None')
    html = html.replace('{{PORT_ROWS}}', port_rows_html)
    html = html.replace('{{ACCORDION}}', accordion_html)
    html = html.replace('{{CMD_ROWS}}', cmd_rows_html)

    report_path = os.path.join(_config.output_dir, 'enumeration_report.html')
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write(html)
    console.print(f"[green]✓[/green] HTML report: [cyan]{report_path}[/cyan]")
    return report_path
