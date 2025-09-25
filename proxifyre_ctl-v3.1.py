#!/usr/bin/env python3
# proxifyre_ctl-v3.1.py — ProxiFyre + WinPkFilter controller

import argparse
import ctypes
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import time
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Iterable, Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

# ----------------- DEFAULT PATHS -----------------
ROOT = Path(__file__).resolve().parent
PROXIFYRE_EXE = ROOT / "ProxiFyre.exe"
INF_PATH_DEFAULT = ROOT / "Windows.Packet.Filter.3.6.1.1.x64" / "drivers" / "win10" / "ndisrd_lwf.inf"
APP_CONFIG = ROOT / "app-config.json"
LWF_COMPONENT_ID = "nt_ndisrd"
DEFAULT_LOG = ROOT / "proxifyre_ctl.log"
SERVICE_NAME = "ProxiFyreService"
# ------------------------------------------------

console = Console()
LOG = logging.getLogger("proxifyre_ctl")
VERBOSE = False

# ----------------- LOGGING -----------------
def setup_logging(log_file: Path, verbose: bool):
    LOG.setLevel(logging.DEBUG)
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
    fh = RotatingFileHandler(log_file, maxBytes=2_000_000, backupCount=3, encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(fmt)
    LOG.addHandler(fh)

    ch = logging.StreamHandler(stream=sys.stderr)
    ch.setLevel(logging.DEBUG if verbose else logging.INFO)
    ch.setFormatter(fmt)
    LOG.addHandler(ch)

# ----------------- UTILITIES -----------------
def is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False

def die(msg: str, code: int = 1):
    LOG.error(msg)
    console.print(Panel(Text(msg, style="bold red"), title="FATAL", style="red"))
    sys.exit(code)

def status_panel(msg: str):
    return console.status(f"[bold cyan]{msg}[/bold cyan]")

def run(cmd: Iterable[str], *, check: bool = True, capture: bool = False,
        timeout: Optional[int] = 60, mask_in_console: bool = False) -> Optional[str]:
    cmd_list = list(map(str, cmd))
    cmd_str = " ".join(cmd_list)
    LOG.debug("RUN: %s", cmd_str)
    if VERBOSE and not mask_in_console:
        console.print(f"[dim]$ {cmd_str}[/dim]")

    try:
        if capture:
            cp = subprocess.run(cmd_list, check=False, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                timeout=timeout)
            LOG.debug("RET=%s\n%s", cp.returncode, (cp.stdout or "").strip())
            if check and cp.returncode != 0:
                raise subprocess.CalledProcessError(cp.returncode, cmd_list, output=cp.stdout)
            return cp.stdout
        else:
            cp = subprocess.run(cmd_list, check=False, timeout=timeout)
            LOG.debug("RET=%s", cp.returncode)
            if check and cp.returncode != 0:
                raise subprocess.CalledProcessError(cp.returncode, cmd_list)
            return None
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"Command timed out: {cmd_str}")

def ensure_tools(require_exe=True, require_inf=True, inf_path: Path | None = None):
    if require_exe and not PROXIFYRE_EXE.exists():
        die(f"Missing ProxiFyre.exe at: {PROXIFYRE_EXE}")
    if require_inf:
        inf = inf_path or INF_PATH_DEFAULT
        if not inf.exists():
            die(f"INF not found at: {inf}")
    for util in ("pnputil.exe", "netcfg.exe", "sc.exe"):
        if shutil.which(util) is None:
            die(f"Required system utility '{util}' not found in PATH (should be in System32).")

# ----------------- DRIVER OPS -----------------
def install_driver(inf: Path, retries: int = 2, backoff: float = 1.0):
    try:
        run(["pnputil", "/add-driver", str(inf), "/install"], check=True, capture=True)
    except subprocess.CalledProcessError as e:
        LOG.warning("pnputil /add-driver returned %s; continuing. Output:\n%s", e.returncode, getattr(e, "output", ""))

    last_err = None
    for attempt in range(1, retries + 2):
        try:
            run(["netcfg.exe", "-l", str(inf), "-c", "s", "-i", LWF_COMPONENT_ID], check=True)
            LOG.info("Driver bound (component %s).", LWF_COMPONENT_ID)
            return
        except Exception as e:
            last_err = e
            LOG.warning("netcfg bind attempt %d failed: %s", attempt, e)
            if attempt <= retries:
                time.sleep(backoff * attempt)
    raise RuntimeError(f"Driver bind failed after retries: {last_err}")

def uninstall_driver(retries: int = 1):
    try:
        run(["netcfg.exe", "-u", LWF_COMPONENT_ID], check=True)
        LOG.info("Driver unbound (component %s).", LWF_COMPONENT_ID)
    except subprocess.CalledProcessError as e:
        LOG.warning("netcfg -u returned %s (may not be bound).", e.returncode)

    try:
        enum_output = run(["pnputil", "/enum-drivers"], check=False, capture=True) or ""
    except Exception as e:
        LOG.warning("pnputil /enum-drivers failed: %s", e)
        enum_output = ""

    cand = set()
    for pub, orig in re.findall(
        r"Published Name\s*:\s*(oem\d+\.inf)\s*.*?Original Name\s*:\s*(.+?)\r?\n",
        enum_output, flags=re.IGNORECASE | re.DOTALL
    ):
        if "ndisrd" in orig.lower() or "winpkfilter" in orig.lower() or "ndisrd_lwf" in orig.lower():
            cand.add(pub.strip())

    if not cand:
        win_inf_dir = Path(os.environ.get("WINDIR", r"C:\Windows")) / "INF"
        for inf in win_inf_dir.glob("oem*.inf"):
            try:
                txt = inf.read_text(errors="ignore")
                if LWF_COMPONENT_ID in txt or "ndisrd" in txt.lower():
                    cand.add(inf.name)
            except Exception:
                continue

    removed = []
    for pub in sorted(cand):
        ok = False
        for attempt in range(1, retries + 2):
            try:
                run(["pnputil", "/delete-driver", pub, "/uninstall", "/force"], check=True, capture=True)
                ok = True
                break
            except subprocess.CalledProcessError as e:
                LOG.warning("delete-driver %s attempt %d failed: %s", pub, attempt, e)
                time.sleep(0.5 * attempt)
        if ok:
            removed.append(pub)
        else:
            LOG.error("Failed to remove %s from driver store.", pub)
    return removed

# ----------------- SERVICE OPS -----------------
def service_state(name: str) -> str:
    """Return 'STOPPED','START_PENDING','RUNNING','STOP_PENDING','PAUSED', or 'UNKNOWN'."""
    try:
        out = run(["sc", "query", name], check=False, capture=True) or ""
    except Exception:
        return "UNKNOWN"
    m = re.search(r"STATE\s*:\s*\d+\s+(\w+)", out)
    return (m.group(1).upper() if m else "UNKNOWN")

def wait_for_service(name: str, want: str = "RUNNING", timeout_s: int = 40, poll_s: float = 0.5) -> bool:
    deadline = time.time() + timeout_s
    last = None
    while time.time() < deadline:
        st = service_state(name)
        if st != last and VERBOSE:
            console.print(f"[dim]{name}: {st}[/dim]")
        if st == want:
            return True
        last = st
        time.sleep(poll_s)
    return False

def proxifyre_install_start():
    run([str(PROXIFYRE_EXE), "install"], check=True)
    # start via app, then verify; if not running, try SCM start once
    run([str(PROXIFYRE_EXE), "start"], check=False)
    if not wait_for_service(SERVICE_NAME, want="RUNNING", timeout_s=40):
        run(["sc", "start", SERVICE_NAME], check=False)
        if not wait_for_service(SERVICE_NAME, want="RUNNING", timeout_s=20):
            raise RuntimeError("ProxiFyre service failed to reach RUNNING (timed out). Check app-config.json and logs.")

def proxifyre_stop():
    try:
        run([str(PROXIFYRE_EXE), "stop"], check=True)
    except subprocess.CalledProcessError as e:
        LOG.warning("ProxiFyre stop returned %s (maybe not running).", e.returncode)

def proxifyre_uninstall():
    try:
        run([str(PROXIFYRE_EXE), "uninstall"], check=True)
    except subprocess.CalledProcessError as e:
        LOG.warning("ProxiFyre uninstall returned %s (maybe not installed).", e.returncode)

# ----------------- CONFIG OPS -----------------
def load_config():
    if APP_CONFIG.exists():
        try:
            with APP_CONFIG.open("r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            LOG.error("Invalid JSON in %s: %s. Backing up.", APP_CONFIG, e)
            try:
                APP_CONFIG.rename(APP_CONFIG.with_suffix(".json.bak"))
            except Exception:
                pass
    return {"logLevel": "Error", "proxies": []}

def save_config(cfg):
    with APP_CONFIG.open("w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)
    LOG.info("Wrote %s", APP_CONFIG)

def upsert_proxy(cfg, exe_path: Path, socks: str, username: Optional[str], password: Optional[str], protos: list[str]):
    exe_path = exe_path.resolve()
    name = exe_path.name
    entry = {
        "appNames": [name, str(exe_path)],
        "socks5ProxyEndpoint": socks,
        "supportedProtocols": protos or ["TCP", "UDP"],
    }
    if username:
        entry["username"] = username
    if password:
        entry["password"] = password

    new_list = []
    replaced = False
    for e in cfg.get("proxies", []):
        names = [n.lower() for n in e.get("appNames", [])]
        if name.lower() in names or str(exe_path).lower() in names:
            new_list.append(entry)
            replaced = True
        else:
            new_list.append(e)
    if not replaced:
        new_list.append(entry)
    cfg["proxies"] = new_list
    return cfg, replaced

def validate_config_for_start():
    try:
        if not APP_CONFIG.exists():
            return (False, f"Missing {APP_CONFIG}")
        with APP_CONFIG.open("r", encoding="utf-8") as f:
            cfg = json.load(f)
        proxies = cfg.get("proxies", [])
        if not isinstance(proxies, list) or not proxies:
            return (False, "No proxies configured in app-config.json")
        for i, e in enumerate(proxies):
            if not e.get("appNames") or not e.get("socks5ProxyEndpoint"):
                return (False, f"Proxy entry #{i+1} missing appNames or socks5ProxyEndpoint")
        return (True, "")
    except Exception as e:
        LOG.exception("Config validation failed")
        return (False, f"Invalid app-config.json: {e}")

# ----------------- COMMANDS -----------------
def cmd_install(inf_path: Path):
    ensure_tools(require_exe=True, require_inf=True, inf_path=inf_path)

    ok, reason = validate_config_for_start()
    if not ok:
        die(f"Refusing to start ProxiFyre: {reason}\n"
            f"Use --config-app to create one, e.g.\n"
            f'  python {Path(__file__).name} --config-app "C:\\Path\\To\\App.exe" --socks 127.0.0.1:1080')

    with status_panel("Installing driver and starting ProxiFyre..."):
        install_driver(inf_path)
        proxifyre_install_start()

    table = Table(box=box.ROUNDED)
    table.add_column("Step", style="bold")
    table.add_column("Result")
    table.add_row("Driver", f"Installed/bound from [bold]{inf_path.name}[/bold]")
    st = service_state(SERVICE_NAME)
    table.add_row("Service", f"ProxiFyre {('running' if st=='RUNNING' else st.lower())}")
    console.print(table)
    LOG.info("Install completed; service state: %s", st)

def cmd_stop():
    ensure_tools(require_exe=True, require_inf=False)
    with status_panel("Stopping ProxiFyre..."):
        proxifyre_stop()
    console.print(Panel("Service stop requested.", title="ProxiFyre", style="green"))
    LOG.info("Stop requested.")

def cmd_uninstall(inf_path: Path):
    ensure_tools(require_exe=False, require_inf=False)
    with status_panel("Uninstalling ProxiFyre and removing driver..."):
        proxifyre_stop()
        proxifyre_uninstall()
        removed = uninstall_driver()

    table = Table(box=box.ROUNDED)
    table.add_column("Action", style="bold")
    table.add_column("Details")
    table.add_row("Service", "Stopped & uninstalled")
    details = f"Unbound; removed {len(removed)} driver store entries"
    if VERBOSE and removed:
        details += f" ({', '.join(removed)})"
    table.add_row("Driver", details)
    console.print(table)
    LOG.info("Uninstall completed. Removed entries: %s", removed)

def cmd_config_app(exe_path: str, socks: str, username: Optional[str], password: Optional[str],
                   protocols_csv: str, log_level: str):
    exe = Path(exe_path)
    if not exe.exists():
        die(f"Target app not found: {exe}")
    protos = [p.strip().upper() for p in protocols_csv.split(",") if p.strip()]
    for p in protos:
        if p not in ("TCP", "UDP"):
            die("supportedProtocols must be TCP and/or UDP (e.g., TCP,UDP)")

    cfg = load_config()
    cfg["logLevel"] = log_level
    cfg, replaced = upsert_proxy(cfg, exe, socks, username, password, protos or ["TCP","UDP"])
    save_config(cfg)

    table = Table(box=box.ROUNDED)
    table.add_column("Field", style="bold")
    table.add_column("Value")
    table.add_row("App", f"{exe.name} ({exe})")
    table.add_row("SOCKS", socks)
    table.add_row("Protocols", ", ".join(protos or ['TCP','UDP']))
    if username or password:
        ux = "*" * len(username or "")
        px = "*" * len(password or "")
        table.add_row("Auth", f"username={ux}  password={px}")
    table.add_row("Config file", str(APP_CONFIG))
    console.print(Panel.fit(table, title=("Updated" if replaced else "Added") + " app-config.json", style="green"))
    LOG.info("Configured app %s via %s (replaced=%s).", exe, APP_CONFIG, replaced)

# ----------------- CLI -----------------
def parse_args():
    p = argparse.ArgumentParser(description="ProxiFyre controller (Rich TUI + logging). Admin needed for install/stop/uninstall.")
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--install", action="store_true", help="Install/bind WinPkFilter driver and install+start ProxiFyre.")
    g.add_argument("--stop", action="store_true", help="Stop ProxiFyre service.")
    g.add_argument("--uninstall", action="store_true", help="Stop/uninstall ProxiFyre and remove driver.")
    g.add_argument("--config-app", type=str, metavar="PATH_TO_EXE", help="Add/update app-config.json entry for this EXE.")

    p.add_argument("--inf", type=str, help="Path to ndisrd_lwf.inf (defaults to Windows.Packet.Filter...\\drivers\\win10).")
    p.add_argument("--socks", type=str, default="127.0.0.1:1080", help="SOCKS5 endpoint for --config-app (host:port).")
    p.add_argument("--username", type=str, default=None, help="SOCKS5 username for --config-app.")
    p.add_argument("--password", type=str, default=None, help="SOCKS5 password for --config-app.")
    p.add_argument("--protocols", type=str, default="TCP,UDP", help="Comma-separated: TCP,UDP.")
    p.add_argument("--log-level", type=str, default="Error", help="Log level for app-config.json (Error, Warning, Info, Debug, All/None).")
    p.add_argument("--verbose", action="store_true", help="Echo underlying commands and show extra details.")
    p.add_argument("--log-file", type=str, default=str(DEFAULT_LOG), help="Path to log file (default proxifyre_ctl.log).")
    return p.parse_args()

def main():
    global VERBOSE
    args = parse_args()
    VERBOSE = args.verbose

    # Logging first
    log_file = Path(args.log_file)
    try:
        setup_logging(log_file, args.verbose)
        LOG.info("===== proxifyre_ctl start =====")
    except Exception as e:
        console.print(Panel(f"Failed to set up logging: {e}", style="red"))
        sys.exit(2)

    if any([args.install, args.stop, args.uninstall]) and not is_admin():
        die("Must run as Administrator for install/stop/uninstall.")

    inf_path = Path(args.inf).resolve() if args.inf else INF_PATH_DEFAULT

    try:
        if args.install:
            cmd_install(inf_path)
        elif args.stop:
            cmd_stop()
        elif args.uninstall:
            cmd_uninstall(inf_path)
        elif args.config_app:
            cmd_config_app(args.config_app, args.socks, args.username, args.password, args.protocols, args.log_level)
        else:
            die("No action selected.")
        console.print(Panel("Done.", style="bold green"))
        LOG.info("Success.")
    except KeyboardInterrupt:
        die("Interrupted by user.", code=130)
    except Exception as e:
        LOG.exception("Unhandled error")
        die(f"Error: {e}", code=1)

if __name__ == "__main__":
    main()
