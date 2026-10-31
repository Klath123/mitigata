"""Serve results + the React UI:  python -m engine.api [results/<run>] [--port 8000]

No run given: the newest finished run under results/ (switch runs in the UI header).
"""
import argparse
import os

import uvicorn

p = argparse.ArgumentParser(prog="python -m engine.api")
p.add_argument("run", nargs="?", help="run folder, e.g. results/firex (default: newest under results/)")
p.add_argument("--port", type=int, default=8000)
p.add_argument("--host", default="127.0.0.1")
a = p.parse_args()
if a.run:
    os.environ["ATTACKSTORY_RUN"] = os.path.abspath(a.run)
from .app import DIST, create_app  # noqa: E402  (reads ATTACKSTORY_RUN)

if not os.path.isdir(os.path.join(DIST, "assets")):
    print("React UI not built: cd frontend && npm ci && npm run build  (serving the fallback page meanwhile)")
print(f"AttackStory UI: http://{a.host}:{a.port}")
uvicorn.run(create_app(), host=a.host, port=a.port, log_level="warning")
