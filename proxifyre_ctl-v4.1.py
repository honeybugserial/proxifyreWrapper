#!/usr/bin/env python3
# proxifyre_ctl-v4.1.py — ProxiFyre + WinPkFilter controller (no app-config ops)

import argparse
import ctypes
import logging
import os
import re
import shutil
import subprocess
import sys
import time
import pyfiglet

from datetime import datetime
from time import sleep
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Iterable, Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box
from rich.spinner import Spinner



# ----------------- DEFAULT PATHS -----------------
ROOT = Path(__file__).resolve().parent
PROXIFYRE_EXE = ROOT / "ProxiFyre.exe"
INF_PATH_DEFAULT = ROOT / "Windows.Packet.Filter.3.6.1.1.x64" / "drivers" / "win10" / "ndisrd_lwf.inf"
LWF_COMPONENT_ID = "nt_ndisrd"
DEFAULT_LOG = ROOT / "logs/proxifyre_ctl.log"
SERVICE_NAME = "ProxiFyreService"
# ------------------------------------------------

# ----------------- SPLASH VARS -----------------
title = "PROXIFYRE CONTROLSING"
ascii_font = "doom"
timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
sleep_time = 2.6
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

def splash_screen(title, ascii_font, timestamp, sleep_time=5):
    os.system('cls' if os.name == 'nt' else 'clear')

    # Title Rule
    console.rule(f"[bold cyan]{title}[/bold cyan]")

    # Generate ASCII art from title (or any string)
    ascii_art = pyfiglet.figlet_format(title, font=ascii_font)
    console.print(ascii_art, style="bold green")

    # Timestamp and Launch Rule
    console.print(f"[dim]Started at: {timestamp}[/]\n")
    console.rule(f"[bold cyan] LAUNCHING [/bold cyan]")

    # Spinner Delay
    with console.status("[bold yellow]Loadings...[/]", spinner="dots"):
        sleep(sleep_time)

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

def rc(cmd: Iterable[str]) -> int:
    """Return process return code without raising."""
    try:
        return subprocess.run(list(map(str, cmd)), check=False,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode
    except Exception:
        return 1

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

def driver_bound() -> bool:
    return rc(["netcfg.exe", "-q", LWF_COMPONENT_ID]) == 0

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
    run([str(PROXIFYRE_EXE), "start"], check=False)
    if not wait_for_service(SERVICE_NAME, want="RUNNING", timeout_s=40):
        run(["sc", "start", SERVICE_NAME], check=False)
        if not wait_for_service(SERVICE_NAME, want="RUNNING", timeout_s=20):
            raise RuntimeError("ProxiFyre service failed to reach RUNNING. Check logs.")

def proxifyre_start_only():
    run([str(PROXIFYRE_EXE), "start"], check=False)
    if not wait_for_service(SERVICE_NAME, want="RUNNING", timeout_s=20):
        run(["sc", "start", SERVICE_NAME], check=False)
        if not wait_for_service(SERVICE_NAME, want="RUNNING", timeout_s=20):
            raise RuntimeError("ProxiFyre service failed to reach RUNNING. Check logs.")

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

# ----------------- COMMANDS -----------------
def cmd_install(inf_path: Path):
    ensure_tools(require_exe=True, require_inf=True, inf_path=inf_path)
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

def cmd_start():
    ensure_tools(require_exe=True, require_inf=False)
    with status_panel("Starting ProxiFyre..."):
        proxifyre_start_only()
    console.print(Panel("Service start requested.", title="ProxiFyre", style="green"))
    LOG.info("Start requested.")

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

def cmd_status(inf_path: Path):
    """
    Show a quick, non-blocking status report:
      - ProxiFyre Windows service state
      - WinPkFilter (ndisrd) binding presence (via `netcfg -s n`)
      - Driver store presence (via `pnputil /enum-drivers`)
    """
    ensure_tools(require_exe=False, require_inf=False)

    # --- Service state ---
    svc_state = service_state(SERVICE_NAME)
    if svc_state == "UNKNOWN":
        svc_msg = "Not installed"
    else:
        svc_msg = svc_state

    # --- Is the LWF bound? (present in network stack) ---
    try:
        netcfg_out = run(["netcfg", "-s", "n"], check=False, capture=True) or ""
    except Exception as e:
        LOG.warning("Failed to query netcfg: %s", e)
        netcfg_out = ""
    lwf_bound = bool(re.search(rf"\b{re.escape(LWF_COMPONENT_ID)}\b", netcfg_out, re.IGNORECASE))

    # --- Is the INF still in the driver store? ---
    try:
        enum_out = run(["pnputil", "/enum-drivers"], check=False, capture=True) or ""
    except Exception as e:
        LOG.warning("Failed to enumerate drivers: %s", e)
        enum_out = ""

    store_hits = []
    for pub, orig in re.findall(
        r"Published Name\s*:\s*(oem\d+\.inf)\s*.*?Original Name\s*:\s*(.+?)\r?\n",
        enum_out, flags=re.IGNORECASE | re.DOTALL
    ):
        if "ndisrd" in orig.lower() or "winpkfilter" in orig.lower() or "ndisrd_lwf" in orig.lower():
            store_hits.append((pub.strip(), orig.strip()))
    in_store = bool(store_hits)

    # --- Render report ---
    table = Table(box=box.ROUNDED)
    table.add_column("Component", style="bold")
    table.add_column("Status")

    table.add_row("Service", svc_msg)
    table.add_row("Driver binding (ndisrd)", "Bound" if lwf_bound else "Not bound")
    table.add_row("Driver store (INF)", "Present" if in_store else "Not present")

    console.print(Panel.fit(table, title="ProxiFyre Status", style="cyan"))

    # Extra hints
    hints = []
    if svc_msg != "RUNNING":
        hints.append("Service is not RUNNING.")
    if not lwf_bound:
        hints.append("WinPkFilter LWF is not bound.")
    if not in_store:
        hints.append("INF not found in driver store.")

    if hints:
        console.print(Panel("\n".join(f"• {h}" for h in hints), title="Notes", style="yellow"))

    LOG.info("Status: service=%s, bound=%s, store=%s",
             svc_msg, lwf_bound, in_store)

# ----------------- INTERACTIVE MENU -----------------
def interactive_menu(inf_path: Path):
    
    console.print(Panel("usage: proxifyre_ctl-v4.py [-h] [--install | --start | --stop | --uninstall | --status] [--inf INF] [--verbose] [--log-file LOG_FILE]", style="cyan", title="CLI Usage"))
    
    #console.print(Panel("No switches provided. Choose an action:", style="cyan", title="ProxiFyre Control Menu"))
    #Style = Style(color="magenta", bgcolor="yellow", italic=True)
    console.print("[bold italic magenta]### ProxiFyre Control Menu ###[/]", justify="left")
    options = [
        ("Install (Driver + Service Then Start)", "install", True),
        ("Uninstall (Stop Pzroxifyre & Service + Remove Driver)", "uninstall", True),
        ("Start Service", "start", True),
        ("Stop Service", "stop", True),
        ("Status (Show Status)", "status", False),
        ("Exit", "exit", False),
    ]

    for idx, (label, _, _) in enumerate(options, start=1):
        console.print(f"[bold]{idx}[/bold]) {label}")

    choice = input("\nSelect [1-{}]: ".format(len(options))).strip()
    if not choice.isdigit() or not (1 <= int(choice) <= len(options)):
        console.print(Panel("Invalid choice.", style="red"))
        return

    _, action, needs_admin = options[int(choice) - 1]
    if action == "exit":
        return

    if needs_admin and not is_admin():
        console.print(Panel("This action requires Administrator privileges. Re-run as Admin.", style="red"))
        return

    try:
        if action == "install":
            ensure_tools(require_exe=True, require_inf=True, inf_path=inf_path)
            ok, reason = validate_config_for_start()
            if not ok:
                die(f"Refusing to start ProxiFyre: {reason}")
            with status_panel("Installing driver and starting ProxiFyre..."):
                install_driver(inf_path)
                proxifyre_install_start()
        elif action == "start":
            cmd_start()
        elif action == "stop":
            cmd_stop()
        elif action == "uninstall":
            cmd_uninstall(inf_path)
        elif action == "status":
            cmd_status(inf_path)

        console.print(Panel("Running is Done.", style="bold green"))
    except Exception as e:
        LOG.exception("Menu action failed")
        die(f"Error: {e}", code=1)

# ----------------- CLI -----------------
def parse_args():
    p = argparse.ArgumentParser(description="ProxiFyre Controller")
    g = p.add_mutually_exclusive_group(required=False)
    g.add_argument("--install", action="store_true", help="Install/Bind WinPkFilter Driver and Install+Start ProxiFyre.")
    g.add_argument("--start", action="store_true", help="Start ProxiFyre Service.")
    g.add_argument("--stop", action="store_true", help="Stop ProxiFyre Service.")
    g.add_argument("--uninstall", action="store_true", help="Stop/Uninstall ProxiFyre and Remove Driver.")
    g.add_argument("--status", action="store_true", help="Show Status.")


    p.add_argument("--inf", type=str, help="Path to ndisrd_lwf.inf (Defaults to Windows.Packet.Filter...\\drivers\\win10).")
    p.add_argument("--verbose", action="store_true", help="Echo Underlying Commands and Show Extra Details.")
    p.add_argument("--log-file", type=str, default=str(DEFAULT_LOG), help="Path to Log File (default logs\proxifyre_ctl.log).")
    
    return p.parse_args()

def main():
    splash_screen(title, ascii_font, timestamp, sleep_time)
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

    if any([args.install, args.start, args.stop, args.uninstall]) and not is_admin():
        die("Must run as Administrator for install/start/stop/uninstall.")

    inf_path = Path(args.inf).resolve() if args.inf else INF_PATH_DEFAULT
    
    try:
        if args.install:
            cmd_install(inf_path)
        elif args.start:
            cmd_start()
        elif args.stop:
            cmd_stop()
        elif args.uninstall:
            cmd_uninstall(inf_path)
        elif args.status:
            cmd_status(Path(args.inf).resolve() if args.inf else INF_PATH_DEFAULT)
        else:
            #die("No action selected.")
            interactive_menu(inf_path)
        #console.print(Panel("Done.", style="bold green"))
        LOG.info("Success.")
    except KeyboardInterrupt:
        die("Interrupted by user.", code=130)
    except Exception as e:
        LOG.exception("Unhandled error")
        die(f"Error: {e}", code=1)

if __name__ == "__main__":
    main()
