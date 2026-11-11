"""SentinelGate AI Desktop Application Launcher (PyWebView + Local Authenticated Server)."""

from __future__ import annotations

import argparse
import os
import socket
import threading
import time

import webview
from werkzeug.serving import make_server

from sentinelgate import __app_name__
from sentinelgate.server import create_app


def _strip_proxy_env_overrides() -> None:
    """Prevent proxy, CA-bundle, and Python debugger injection env vars from exposing secrets."""
    for key in (
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
        "REQUESTS_CA_BUNDLE",
        "CURL_CA_BUNDLE",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "PYTHONINSPECT",
        "PYTHONBREAKPOINT",
        "PYTHONSTARTUP",
        "PYTHONVERBOSE",
    ):
        os.environ.pop(key, None)
        os.environ.pop(key.lower(), None)


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def main() -> None:
    _strip_proxy_env_overrides()
    parser = argparse.ArgumentParser(description=f"{__app_name__} Desktop Controller")
    parser.add_argument(
        "--init-data",
        action="store_true",
        help="Initialize editable data JSON files and exit cleanly.",
    )
    parser.add_argument(
        "--headless",
        action="store_true",
        help="Start local server only (for automated API verification).",
    )
    parser.add_argument("--port", type=int, default=0, help="Port to bind local server on.")
    args, _ = parser.parse_known_args()

    if args.init_data:
        from sentinelgate.core.storage import StorageManager

        StorageManager()
        return

    port = args.port or _find_free_port()
    app, token = create_app()
    server = make_server("127.0.0.1", port, app, threaded=True)

    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    url = f"http://127.0.0.1:{port}/"
    if args.headless:
        print(f"HEADLESS_READY url={url} token={token}", flush=True)
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            server.shutdown()
        return

    window = webview.create_window(
        title=f"{__app_name__} — Secondary Strict Web Filter & Threat Hunter",
        url=url,
        width=1340,
        height=860,
        min_size=(1060, 700),
        background_color="#090d16",
        text_select=True,
    )

    try:
        # debug=False disables DevTools / inspect element in the compiled desktop shell
        webview.start(debug=False)
    finally:
        server.shutdown()
        os._exit(0)


if __name__ == "__main__":
    main()
