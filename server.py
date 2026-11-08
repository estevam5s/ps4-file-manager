#!/usr/bin/env python3
"""PS4 GoldHEN File Manager v3 — FTP web file manager with large file support."""

import base64
import json
import os
import struct
import tempfile
import threading
import time
import uuid
from ftplib import FTP
from io import BytesIO
from urllib.parse import unquote

from flask import Flask, Response, request, jsonify, send_file, send_from_directory, stream_with_context

app = Flask(__name__, static_folder="static")
app.config["MAX_CONTENT_LENGTH"] = 60 * 1024 * 1024 * 1024  # 60 GB

PS4_IP = os.environ.get("PS4_IP", "192.168.1.101")
PS4_PORT = int(os.environ.get("PS4_PORT", "2121"))

# Transfer tracking
transfers = {}
transfers_lock = threading.Lock()

READONLY_PATHS = ("/", "/dev", "/system", "/system_ex", "/preinst", "/preinst2", "/adm")
TEMP_DIR = tempfile.mkdtemp(prefix="ps4fm_")


@app.after_request
def add_cors(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, DELETE, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, X-Filename, X-Destination, X-Transfer-Id, Content-Length"
    return response


def get_ftp():
    ftp = FTP()
    ftp.connect(PS4_IP, PS4_PORT, timeout=120)
    ftp.login("", "")
    ftp.encoding = "utf-8"
    return ftp


def sanitize_ftp_filename(name):
    """Keep original name but remove characters that break FTP STOR."""
    name = name.replace("\x00", "").strip()
    if not name:
        name = "unnamed.pkg"
    return name


def ensure_dir_exists(ftp, path):
    """Create remote directory if it doesn't exist."""
    try:
        ftp.cwd(path)
        ftp.cwd("/")
    except:
        try:
            ftp.mkd(path)
        except:
            pass


def parse_list_line(line):
    parts = line.split(None, 8)
    if len(parts) < 9:
        return None
    perms = parts[0]
    size = int(parts[4]) if parts[4].isdigit() else 0
    date_str = f"{parts[5]} {parts[6]} {parts[7]}"
    name = parts[8]
    if name in (".", ".."):
        return None
    return {
        "name": name,
        "is_dir": perms.startswith("d"),
        "size": size,
        "permissions": perms,
        "date": date_str,
    }


def parse_param_sfo(data):
    if len(data) < 20 or data[:4] != b"\x00PSF":
        return {}
    key_off = struct.unpack_from("<I", data, 8)[0]
    data_off = struct.unpack_from("<I", data, 12)[0]
    count = struct.unpack_from("<I", data, 16)[0]
    result = {}
    for i in range(count):
        e = 20 + i * 16
        if e + 16 > len(data):
            break
        ko, fmt, dl, _, do = struct.unpack_from("<HHIII", data, e)
        ks = key_off + ko
        ke = data.index(b"\x00", ks) if ks < len(data) else ks
        key = data[ks:ke].decode("utf-8", errors="replace")
        vs = data_off + do
        if fmt == 0x0204:
            result[key] = data[vs:vs + dl].rstrip(b"\x00").decode("utf-8", errors="replace")
        elif fmt == 0x0404 and dl == 4:
            result[key] = str(struct.unpack_from("<I", data, vs)[0])
    return result


def _rmdir_recursive(ftp, path):
    lines = []
    ftp.retrlines(f"LIST {path}", lines.append)
    for line in lines:
        item = parse_list_line(line)
        if not item:
            continue
        full = f"{path.rstrip('/')}/{item['name']}"
        if item["is_dir"]:
            _rmdir_recursive(ftp, full)
        else:
            ftp.delete(full)
    ftp.rmd(path)


def _list_items(ftp, path):
    lines = []
    try:
        ftp.retrlines(f"LIST {path}", lines.append)
    except:
        return []
    items = [parse_list_line(l) for l in lines]
    return [i for i in items if i]


def _scan_pkgs_recursive(ftp, path, depth=0, max_depth=2):
    pkgs = []
    if depth > max_depth:
        return pkgs
    items = _list_items(ftp, path)
    for item in items:
        full = f"{path.rstrip('/')}/{item['name']}"
        if not item["is_dir"] and item["name"].lower().endswith(".pkg") and not item["name"].startswith("._"):
            pkgs.append({"name": item["name"], "path": full, "size": item["size"], "date": item["date"]})
        elif item["is_dir"] and depth < max_depth:
            pkgs.extend(_scan_pkgs_recursive(ftp, full, depth + 1, max_depth))
    return pkgs


def _copy_on_ps4(ftp, src, dst, transfer_id):
    """Copy a file within the PS4 by downloading and re-uploading through memory pipe."""
    buf = BytesIO()
    total = [0]
    start = time.time()

    # Get file size first
    lines = []
    parent = src.rsplit("/", 1)[0] or "/"
    ftp.retrlines(f"LIST {parent}", lines.append)
    file_size = 0
    fname = src.rsplit("/", 1)[-1]
    for l in lines:
        item = parse_list_line(l)
        if item and item["name"] == fname:
            file_size = item["size"]
            break

    def on_block(data):
        buf.write(data)
        total[0] += len(data)
        elapsed = time.time() - start
        speed = total[0] / elapsed if elapsed > 0 else 0
        with transfers_lock:
            if transfer_id in transfers:
                transfers[transfer_id].update({
                    "transferred": total[0],
                    "total": file_size,
                    "speed": speed,
                    "phase": "downloading",
                })

    ftp.retrbinary(f"RETR {src}", on_block, blocksize=262144)

    with transfers_lock:
        if transfer_id in transfers:
            transfers[transfer_id]["phase"] = "uploading"

    buf.seek(0)
    uploaded = [0]
    start2 = time.time()
    orig_read = buf.read

    def tracked_read(size=8192):
        data = orig_read(size)
        if data:
            uploaded[0] += len(data)
            elapsed = time.time() - start2
            speed = uploaded[0] / elapsed if elapsed > 0 else 0
            with transfers_lock:
                if transfer_id in transfers:
                    transfers[transfer_id].update({
                        "transferred": uploaded[0],
                        "speed": speed,
                        "phase": "uploading",
                    })
        return data

    buf.read = tracked_read
    ftp.storbinary(f"STOR {dst}", buf, blocksize=262144)


# ── Routes ──

@app.route("/")
def index():
    return send_from_directory("static", "index.html")


@app.route("/favicon.ico")
def favicon():
    return send_from_directory("static", "favicon.svg", mimetype="image/svg+xml")


@app.route("/api/status")
def api_status():
    try:
        ftp = get_ftp()
        welcome = ftp.getwelcome()
        ftp.quit()
        return jsonify({"connected": True, "server": welcome, "ip": PS4_IP, "port": PS4_PORT})
    except Exception as e:
        return jsonify({"connected": False, "error": str(e), "ip": PS4_IP, "port": PS4_PORT})


@app.route("/api/list")
def api_list():
    path = request.args.get("path", "/")
    try:
        ftp = get_ftp()
        items = _list_items(ftp, path)
        items.sort(key=lambda x: (not x["is_dir"], x["name"].lower()))
        ftp.quit()
        return jsonify({"path": path, "items": items})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/download")
def api_download():
    path = request.args.get("path", "")
    if not path:
        return jsonify({"error": "No path"}), 400
    try:
        ftp = get_ftp()
        ftp.sock.settimeout(600)
        tmp = tempfile.NamedTemporaryFile(delete=False, dir=TEMP_DIR, suffix=".dl")
        tmp_path = tmp.name
        ftp.retrbinary(f"RETR {path}", tmp.write, blocksize=262144)
        tmp.close()
        ftp.quit()
        name = path.rsplit("/", 1)[-1]
        resp = send_file(tmp_path, as_attachment=True, download_name=name, mimetype="application/octet-stream")
        threading.Timer(120, lambda p=tmp_path: os.path.exists(p) and os.remove(p)).start()
        return resp
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/upload", methods=["POST"])
def api_upload():
    dest = request.form.get("path", "/mnt/usb0")
    if dest in READONLY_PATHS:
        return jsonify({"error": f"Destino '{dest}' e somente leitura. Use /mnt/usb0 ou /user/app"}), 400
    f = request.files.get("file")
    if not f:
        return jsonify({"error": "No file"}), 400
    try:
        ftp = get_ftp()
        filename = sanitize_ftp_filename(f.filename)
        ensure_dir_exists(ftp, dest)
        remote = f"{dest.rstrip('/')}/{filename}"
        ftp.storbinary(f"STOR {remote}", f.stream, blocksize=262144)
        ftp.quit()
        return jsonify({"ok": True, "path": remote})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/upload_chunked", methods=["POST"])
def api_upload_chunked():
    """Stream upload with progress tracking via transfer_id."""
    dest = request.form.get("path", "/mnt/usb0")
    if dest in READONLY_PATHS:
        return jsonify({"error": f"Destino '{dest}' e somente leitura. Use /mnt/usb0 ou /user/app"}), 400
    transfer_id = request.form.get("transfer_id", str(uuid.uuid4()))
    f = request.files.get("file")
    if not f:
        return jsonify({"error": "No file"}), 400

    filename = sanitize_ftp_filename(f.filename)
    remote = f"{dest.rstrip('/')}/{filename}"
    total_size = int(request.form.get("size", 0))

    with transfers_lock:
        transfers[transfer_id] = {
            "id": transfer_id,
            "type": "upload",
            "filename": filename,
            "src": "local",
            "dst": remote,
            "total": total_size,
            "transferred": 0,
            "speed": 0,
            "status": "active",
            "phase": "uploading",
            "started": time.time(),
        }

    try:
        ftp = get_ftp()
        uploaded = [0]
        start = time.time()

        class TrackedStream:
            def read(self, size=262144):
                data = f.stream.read(size)
                if data:
                    uploaded[0] += len(data)
                    elapsed = time.time() - start
                    speed = uploaded[0] / elapsed if elapsed > 0 else 0
                    with transfers_lock:
                        if transfer_id in transfers:
                            transfers[transfer_id].update({
                                "transferred": uploaded[0],
                                "speed": speed,
                            })
                return data

        ftp.storbinary(f"STOR {remote}", TrackedStream(), blocksize=262144)
        ftp.quit()

        with transfers_lock:
            if transfer_id in transfers:
                transfers[transfer_id]["status"] = "done"

        return jsonify({"ok": True, "path": remote, "transfer_id": transfer_id})
    except Exception as e:
        with transfers_lock:
            if transfer_id in transfers:
                transfers[transfer_id].update({"status": "error", "error": str(e)})
        return jsonify({"error": str(e)}), 500


@app.route("/api/delete", methods=["POST"])
def api_delete():
    data = request.json
    path = data.get("path", "")
    is_dir = data.get("is_dir", False)
    if not path:
        return jsonify({"error": "No path"}), 400
    try:
        ftp = get_ftp()
        if is_dir:
            _rmdir_recursive(ftp, path)
        else:
            ftp.delete(path)
        ftp.quit()
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/mkdir", methods=["POST"])
def api_mkdir():
    data = request.json
    path = data.get("path", "")
    if not path:
        return jsonify({"error": "No path"}), 400
    try:
        ftp = get_ftp()
        ftp.mkd(path)
        ftp.quit()
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/rename", methods=["POST"])
def api_rename():
    data = request.json
    old = data.get("old", "")
    new = data.get("new", "")
    if not old or not new:
        return jsonify({"error": "Missing paths"}), 400
    try:
        ftp = get_ftp()
        ftp.rename(old, new)
        ftp.quit()
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/copy", methods=["POST"])
def api_copy():
    """Copy or move a file within the PS4 filesystem."""
    data = request.json
    src = data.get("src", "")
    dst = data.get("dst", "")
    mode = data.get("mode", "copy")  # copy or move
    if not src or not dst:
        return jsonify({"error": "Missing src/dst"}), 400

    transfer_id = str(uuid.uuid4())
    src_name = src.rsplit("/", 1)[-1]
    dst_full = f"{dst.rstrip('/')}/{src_name}"

    with transfers_lock:
        transfers[transfer_id] = {
            "id": transfer_id,
            "type": mode,
            "filename": src_name,
            "src": src,
            "dst": dst_full,
            "total": 0,
            "transferred": 0,
            "speed": 0,
            "status": "active",
            "phase": "starting",
            "started": time.time(),
        }

    def do_copy():
        try:
            ftp = get_ftp()
            _copy_on_ps4(ftp, src, dst_full, transfer_id)

            if mode == "move":
                with transfers_lock:
                    if transfer_id in transfers:
                        transfers[transfer_id]["phase"] = "deleting source"
                ftp.delete(src)

            ftp.quit()
            with transfers_lock:
                if transfer_id in transfers:
                    transfers[transfer_id]["status"] = "done"
        except Exception as e:
            with transfers_lock:
                if transfer_id in transfers:
                    transfers[transfer_id].update({"status": "error", "error": str(e)})

    thread = threading.Thread(target=do_copy, daemon=True)
    thread.start()
    return jsonify({"ok": True, "transfer_id": transfer_id})


@app.route("/api/preview")
def api_preview():
    path = request.args.get("path", "")
    if not path:
        return jsonify({"error": "No path"}), 400
    try:
        ftp = get_ftp()
        buf = BytesIO()
        ftp.retrbinary(f"RETR {path}", buf.write)
        ftp.quit()
        data = buf.getvalue()

        if path.endswith(".sfo"):
            return jsonify({"type": "sfo", "data": parse_param_sfo(data)})
        if path.endswith(".json"):
            return jsonify({"type": "json", "data": json.loads(data)})
        if path.endswith((".xml", ".txt", ".log", ".cfg", ".ini", ".conf", ".sh", ".py", ".md", ".html", ".css", ".js")):
            return jsonify({"type": "text", "data": data.decode("utf-8", errors="replace")[:100000]})
        if path.endswith((".png", ".jpg", ".jpeg", ".gif", ".bmp")):
            ext = path.rsplit(".", 1)[-1].lower()
            mime = {"png": "image/png", "jpg": "image/jpeg", "jpeg": "image/jpeg", "gif": "image/gif", "bmp": "image/bmp"}.get(ext, "application/octet-stream")
            return jsonify({"type": "image", "data": f"data:{mime};base64,{base64.b64encode(data).decode()}"})
        return jsonify({"type": "binary", "size": len(data), "hex": data[:256].hex()})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/apps")
def api_apps():
    try:
        ftp = get_ftp()
        entries = []
        try:
            items = ftp.nlst("/user/app")
        except:
            items = []
        folders = sorted(i.rsplit("/", 1)[-1] for i in items if i.rsplit("/", 1)[-1] not in (".", ".."))

        for tid in folders:
            info = {"title_id": tid, "title": tid, "version": "—", "category": "—", "content_id": "—", "icon": None}
            buf = BytesIO()
            try:
                ftp.retrbinary(f"RETR /system_data/priv/appmeta/{tid}/param.sfo", buf.write)
                sfo = parse_param_sfo(buf.getvalue())
                info["title"] = sfo.get("TITLE", tid)
                info["version"] = sfo.get("APP_VER", "—")
                info["category"] = sfo.get("CATEGORY", "—")
                info["content_id"] = sfo.get("CONTENT_ID", "—")
            except:
                pass
            icon_buf = BytesIO()
            try:
                ftp.retrbinary(f"RETR /user/appmeta/{tid}/icon0.png", icon_buf.write)
                info["icon"] = f"data:image/png;base64,{base64.b64encode(icon_buf.getvalue()).decode()}"
            except:
                pass
            entries.append(info)

        ftp.quit()
        return jsonify({"apps": entries})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/uninstall", methods=["POST"])
def api_uninstall():
    data = request.json
    tid = data.get("title_id", "")
    if not tid or len(tid) > 20:
        return jsonify({"error": "Invalid title_id"}), 400
    try:
        ftp = get_ftp()
        removed = []
        for d in [f"/user/app/{tid}", f"/user/appmeta/{tid}", f"/system_data/priv/appmeta/{tid}"]:
            try:
                _rmdir_recursive(ftp, d)
                removed.append(d)
            except:
                pass
        buf = BytesIO()
        try:
            ftp.retrbinary("RETR /user/bgft/pushlist/game.dat", buf.write)
            game_data = buf.getvalue()
            new_data = game_data.replace(f"{tid}\x00".encode(), b"")
            if new_data != game_data:
                ftp.storbinary("STOR /user/bgft/pushlist/game.dat", BytesIO(new_data))
                removed.append("bgft/pushlist")
        except:
            pass
        try:
            tasks = ftp.nlst("/user/bgft/task")
            for task in tasks:
                tname = task.rsplit("/", 1)[-1]
                if tname in (".", ".."):
                    continue
                for pdb in ("d0.pdb", "d1.pdb"):
                    pbuf = BytesIO()
                    try:
                        ftp.retrbinary(f"RETR {task}/{pdb}", pbuf.write)
                        if tid.encode() in pbuf.getvalue():
                            _rmdir_recursive(ftp, task)
                            removed.append(f"bgft/task/{tname}")
                            break
                    except:
                        pass
        except:
            pass
        ftp.quit()
        return jsonify({"ok": True, "removed": removed})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/scan_usb")
def api_scan_usb():
    """Scan USB drives for .pkg files."""
    try:
        ftp = get_ftp()
        result = {}
        for usb in ("/mnt/usb0", "/mnt/usb1", "/mnt/usb2", "/mnt/usb3"):
            items = _list_items(ftp, usb)
            if items:
                pkgs = _scan_pkgs_recursive(ftp, usb)
                result[usb] = {"mounted": True, "pkgs": pkgs, "total_items": len(items)}
            else:
                result[usb] = {"mounted": False, "pkgs": [], "total_items": 0}
        ftp.quit()
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/transfers")
def api_transfers():
    """Get current transfer status."""
    with transfers_lock:
        active = {k: v for k, v in transfers.items()}
    return jsonify(active)


@app.route("/api/transfers/<tid>")
def api_transfer_status(tid):
    with transfers_lock:
        t = transfers.get(tid)
    if not t:
        return jsonify({"error": "Not found"}), 404
    return jsonify(t)


@app.route("/api/transfers/<tid>", methods=["DELETE"])
def api_transfer_delete(tid):
    with transfers_lock:
        transfers.pop(tid, None)
    return jsonify({"ok": True})


@app.route("/api/disk_usage")
def api_disk_usage():
    """Get approximate disk usage info."""
    try:
        ftp = get_ftp()
        app_items = _list_items(ftp, "/user/app")
        total_size = 0
        for item in app_items:
            if item["is_dir"]:
                sub = _list_items(ftp, f"/user/app/{item['name']}")
                for s in sub:
                    if s["name"] == "app.pkg":
                        total_size += s["size"]
        ftp.quit()
        return jsonify({"app_count": len(app_items), "total_pkg_size": total_size})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/upload_stream", methods=["POST", "OPTIONS"])
def api_upload_stream():
    """Stream upload via raw body — no multipart, no memory buffering. For large files (>1GB)."""
    if request.method == "OPTIONS":
        return "", 204
    filename = unquote(request.headers.get("X-Filename", "upload.pkg"))
    dest = request.headers.get("X-Destination", "/mnt/usb0")
    transfer_id = request.headers.get("X-Transfer-Id", str(uuid.uuid4()))
    total_size = int(request.headers.get("Content-Length", 0))

    if dest in READONLY_PATHS:
        return jsonify({"error": f"Destino '{dest}' e somente leitura"}), 400

    filename = sanitize_ftp_filename(filename)
    remote = f"{dest.rstrip('/')}/{filename}"

    with transfers_lock:
        transfers[transfer_id] = {
            "id": transfer_id, "type": "upload", "filename": filename,
            "src": "local", "dst": remote, "total": total_size,
            "transferred": 0, "speed": 0, "status": "active",
            "phase": "uploading", "started": time.time(),
        }

    try:
        ftp = get_ftp()
        ensure_dir_exists(ftp, dest)
        uploaded = [0]
        start = time.time()

        class StreamWrapper:
            def read(self, size=262144):
                data = request.stream.read(size)
                if data:
                    uploaded[0] += len(data)
                    elapsed = time.time() - start
                    speed = uploaded[0] / elapsed if elapsed > 0 else 0
                    with transfers_lock:
                        if transfer_id in transfers:
                            transfers[transfer_id].update({
                                "transferred": uploaded[0], "speed": speed,
                            })
                return data

        ftp.storbinary(f"STOR {remote}", StreamWrapper(), blocksize=262144)
        ftp.quit()

        with transfers_lock:
            if transfer_id in transfers:
                transfers[transfer_id]["status"] = "done"

        return jsonify({"ok": True, "path": remote, "transfer_id": transfer_id})
    except Exception as e:
        with transfers_lock:
            if transfer_id in transfers:
                transfers[transfer_id].update({"status": "error", "error": str(e)})
        return jsonify({"error": str(e)}), 500


@app.route("/api/system_info")
def api_system_info():
    try:
        ftp = get_ftp()
        ftp.sock.settimeout(60)
        info = {"ip": PS4_IP, "port": PS4_PORT, "firmware": "", "welcome": ftp.getwelcome(),
                "app_count": 0, "total_pkg_size": 0, "app_details": [], "usb": {}}
        buf = BytesIO()
        try:
            ftp.retrbinary("RETR /system_data/priv/appmeta/NPXS20001/param.sfo", buf.write)
            sfo = parse_param_sfo(buf.getvalue())
            info["firmware"] = sfo.get("APP_VER", "")
        except:
            pass
        app_items = _list_items(ftp, "/user/app")
        info["app_count"] = len(app_items)
        total_size = 0
        for item in app_items:
            if item["is_dir"]:
                sub = _list_items(ftp, f"/user/app/{item['name']}")
                pkg_size = 0
                for s in sub:
                    if s["name"] == "app.pkg":
                        pkg_size = s["size"]
                        total_size += s["size"]
                info["app_details"].append({"tid": item["name"], "size": pkg_size})
        info["total_pkg_size"] = total_size
        for usb in ("/mnt/usb0", "/mnt/usb1", "/mnt/usb2", "/mnt/usb3"):
            items = _list_items(ftp, usb)
            if items:
                total_usb = sum(i["size"] for i in items if not i["is_dir"])
                info["usb"][usb] = {"mounted": True, "items": len(items), "files_size": total_usb}
            else:
                info["usb"][usb] = {"mounted": False}
        ftp.quit()
        return jsonify(info)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    print(f"\n  PS4 File Manager v3")
    print(f"  PS4: {PS4_IP}:{PS4_PORT}")
    print(f"  Web: http://localhost:8090\n")
    app.run(host="0.0.0.0", port=8090, debug=False, threaded=True)
