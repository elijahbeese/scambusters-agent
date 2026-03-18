"""
app.py — ScamBusters Agent v1.0 Flask Dashboard
Routes: bounty board, paste intake, live pipeline, report viewer,
        takedown approval, submission packager, stats.
"""

import os
import json
import queue
import threading
from datetime import datetime
from flask import (Flask, render_template, request, jsonify,
                   redirect, url_for, Response, stream_with_context)
from dotenv import load_dotenv

load_dotenv()

from scripts.bounty_parser    import parse_bounty, validate_bounty
from scripts.bounty_store     import (add_bounty, get_all_bounties, get_bounty,
                                       get_bounty_by_id, update_status,
                                       get_investigation, get_stats)
from scripts.submission_packager import format_email_body

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "dev_scambusters_2026")

# SSE progress queues keyed by bounty_id
progress_queues: dict[str, queue.Queue] = {}


# ─────────────────────────────────────────────
# DASHBOARD
# ─────────────────────────────────────────────

@app.route("/")
def index():
    bounties = get_all_bounties()
    stats    = get_stats()
    return render_template("index.html", bounties=bounties, stats=stats)


# ─────────────────────────────────────────────
# BOUNTY INTAKE
# ─────────────────────────────────────────────

@app.route("/intake", methods=["GET", "POST"])
def intake():
    if request.method == "GET":
        return render_template("intake.html")

    raw = request.form.get("raw_paste", "").strip()
    if not raw:
        return render_template("intake.html", error="Paste is empty.")

    parsed = parse_bounty(raw)
    valid, errors = validate_bounty(parsed)

    if not valid:
        return render_template("intake.html",
                               error=f"Parse failed: {'; '.join(errors)}",
                               raw=raw)

    db_id = add_bounty(parsed)
    return redirect(url_for("bounty_detail", bounty_id=parsed["bounty_id"]))


# ─────────────────────────────────────────────
# BOUNTY DETAIL + INVESTIGATION TRIGGER
# ─────────────────────────────────────────────

@app.route("/bounty/<bounty_id>")
def bounty_detail(bounty_id):
    bounty = get_bounty(bounty_id)
    if not bounty:
        return "Bounty not found", 404
    investigation = get_investigation(bounty_id, bounty["domain"])
    return render_template("bounty.html", bounty=bounty, investigation=investigation)


@app.route("/bounty/<bounty_id>/investigate", methods=["POST"])
def start_investigation(bounty_id):
    """Kick off investigation in a background thread with SSE progress."""
    bounty = get_bounty(bounty_id)
    if not bounty:
        return jsonify({"error": "Bounty not found"}), 404
    if bounty["status"] in ("investigating", "complete", "approved"):
        return jsonify({"error": f"Already {bounty['status']}"}), 400

    q = queue.Queue()
    progress_queues[bounty_id] = q

    def run():
        from agent import run_investigation
        def cb(stage, msg):
            q.put({"stage": stage, "message": msg,
                   "ts": datetime.utcnow().strftime("%H:%M:%S")})
        try:
            run_investigation(bounty, progress_callback=cb)
        except Exception as e:
            q.put({"stage": "error", "message": str(e),
                   "ts": datetime.utcnow().strftime("%H:%M:%S")})
        finally:
            q.put(None)  # sentinel

    threading.Thread(target=run, daemon=True).start()
    return jsonify({"status": "started"})


@app.route("/bounty/<bounty_id>/progress")
def progress_stream(bounty_id):
    """SSE endpoint — streams pipeline progress to the UI in real time."""
    def generate():
        q = progress_queues.get(bounty_id)
        if not q:
            yield "data: {\"stage\":\"error\",\"message\":\"No active investigation\"}\n\n"
            return
        while True:
            try:
                event = q.get(timeout=30)
                if event is None:
                    yield "data: {\"stage\":\"done\",\"message\":\"Complete\"}\n\n"
                    break
                yield f"data: {json.dumps(event)}\n\n"
            except queue.Empty:
                yield "data: {\"stage\":\"ping\",\"message\":\"...\"}\n\n"

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"}
    )


# ─────────────────────────────────────────────
# REPORT VIEWER
# ─────────────────────────────────────────────

@app.route("/bounty/<bounty_id>/report")
def view_report(bounty_id):
    bounty = get_bounty(bounty_id)
    if not bounty:
        return "Not found", 404
    investigation = get_investigation(bounty_id, bounty["domain"])
    return render_template("report.html", bounty=bounty, investigation=investigation)


# ─────────────────────────────────────────────
# TAKEDOWN APPROVAL
# ─────────────────────────────────────────────

@app.route("/bounty/<bounty_id>/approve", methods=["POST"])
def approve_takedown(bounty_id):
    bounty = get_bounty(bounty_id)
    if not bounty:
        return jsonify({"error": "Not found"}), 404

    update_status(bounty_id, "approved")
    investigation = get_investigation(bounty_id, bounty["domain"])
    return jsonify({
        "status": "approved",
        "registrar_email": investigation.get("takedown_registrar", {}).get("email_draft"),
        "hosting_email":   investigation.get("takedown_hosting", {}).get("email_draft"),
    })


# ─────────────────────────────────────────────
# SUBMISSION PACKAGE
# ─────────────────────────────────────────────

@app.route("/bounty/<bounty_id>/submission")
def submission_package(bounty_id):
    bounty = get_bounty(bounty_id)
    if not bounty:
        return "Not found", 404
    investigation = get_investigation(bounty_id, bounty["domain"])
    pkg  = investigation.get("submission_package", {}) if investigation else {}
    body = format_email_body(pkg) if pkg else "No package available yet."
    return render_template("submission.html",
                           bounty=bounty, package=pkg, email_body=body)


# ─────────────────────────────────────────────
# API ENDPOINTS (for JS fetch calls)
# ─────────────────────────────────────────────

@app.route("/api/bounties")
def api_bounties():
    return jsonify(get_all_bounties())


@app.route("/api/stats")
def api_stats():
    return jsonify(get_stats())


@app.route("/api/bounty/<bounty_id>/investigation")
def api_investigation(bounty_id):
    bounty = get_bounty(bounty_id)
    if not bounty:
        return jsonify({"error": "Not found"}), 404
    inv = get_investigation(bounty_id, bounty["domain"])
    return jsonify(inv or {})


if __name__ == "__main__":
    from scripts.bounty_store import init_db
    init_db()
    app.run(
        debug=os.getenv("FLASK_DEBUG", "True") == "True",
        port=5000,
        threaded=True
    )
