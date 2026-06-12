"""
Cross-chain trust walkthrough — executable version of docs/concepts/cross_chain_trust.md.

Runs the CLI commands shown in the concept guide step by step and prints
the files created at each panel so you can see them alongside the docs.

Run as a script:   python tests/cross_chain.py
Run as a test:     pytest tests/cross_chain.py -s
"""
from __future__ import annotations

import json
import time
import tempfile
from pathlib import Path

from typer.testing import CliRunner
import aiohttp

from certified.certified import app
from certified.message import app as msg
from certified.test import child_process

runner = CliRunner()

# Max seconds to wait for a server to become ready
_CONNECT_TIMEOUT = 5.0


# ── helpers ───────────────────────────────────────────────────────────────────

def banner(text: str) -> None:
    width = 70
    print("\n" + "─" * width)
    print(f"  {text}")
    print("─" * width)


def cli_run(args: list[str], config: Path, expect_exit: int = 0) -> str:
    """Invoke the certified CLI and assert the exit code."""
    full_args = args + ["--config", str(config)]
    result = runner.invoke(app, full_args)
    if result.exit_code != expect_exit:
        raise AssertionError(
            f"certified {' '.join(args)} exited {result.exit_code}\n"
            f"stdout: {result.stdout}\nexc: {result.exception}"
        )
    return result.stdout


def tree(root: Path, indent: str = "") -> None:
    """Print a directory tree, hiding private key contents."""
    for child in sorted(root.iterdir()):
        if child.name.endswith(".key"):
            print(f"{indent}├── {child.name}  (private key — not shown)")
        elif child.is_dir():
            print(f"{indent}├── {child.name}/")
            tree(child, indent + "│   ")
        else:
            print(f"{indent}├── {child.name}")


def print_file(path: Path, label: str | None = None) -> None:
    if not path.exists():
        print(f"  [not found: {path}]")
        return
    print(f"\n{'─'*4} {label or path.name} {'─'*4}")
    print(path.read_text().rstrip())


def run_echo_server(config: Path, port: int) -> None:
    runner.invoke(app, [
        "serve", "examples.echo:app",
        f"https://127.0.0.1:{port}",
        "--config", str(config),
    ])


def can_connect(client_cfg: Path, server_cfg: Path,
                alias: str, port: int) -> bool:
    """
    Return True if the client can reach the echo server using *alias* as the
    service name (looked up in known_servers/<alias>.yaml). The port is
    supplied in the alias URL; the service definition must NOT include a port
    (i.e. set service URL to 'https://127.0.0.1', port comes from here).

    Returns False on SSL rejection. Raises TimeoutError if server never comes up.
    """
    url = f"https://{alias}:{port}/echo/ping"
    deadline = time.monotonic() + _CONNECT_TIMEOUT

    with child_process(run_echo_server, server_cfg, port):
        while time.monotonic() < deadline:
            r = runner.invoke(msg, [url, "--config", str(client_cfg)])
            if r.exit_code == 0:
                return True
            exc = r.exception
            s = str(exc) if exc else ""
            # Definitive SSL auth rejection — stop immediately
            if isinstance(exc, aiohttp.ClientSSLError):
                return False
            if "CERTIFICATE_VERIFY_FAILED" in s:
                return False
            # Transient: server not yet listening, DNS alias not resolved, or
            # message command exited non-zero before the server was ready
            time.sleep(0.05)
        raise TimeoutError(
            f"Server at {url} did not become ready within {_CONNECT_TIMEOUT}s"
        )


# ── the three-panel walkthrough ───────────────────────────────────────────────

def run_walkthrough(tmp: Path) -> None:
    alice = tmp / "alice"        # client identity
    ornl  = tmp / "ornl-api"     # Org1 server
    nist  = tmp / "nist-api"     # Org2 server

    # ── Panel 1: Independent parties ─────────────────────────────────────────
    banner("PANEL 1 — Independent parties: each runs 'certified init'")

    cli_run(["init", "Alice Nguyen", "--email", "alice.nguyen@ornl.gov"], alice)
    cli_run(["init",
             "--org",  "Oak Ridge National Laboratory",
             "--unit", "Materials Science",
             "--host", "127.0.0.1"], ornl)
    cli_run(["init",
             "--org",  "National Institute of Standards and Technology",
             "--unit", "Cybersecurity",
             "--host", "127.0.0.1"], nist)

    print("\nAlice's directory (before any introductions):")
    tree(alice)
    print("\nORNL API directory:")
    tree(ornl)

    # The ORNL server's self-trust only covers its own CA — Alice is rejected.
    print("\n✓  No cross-trust exists yet.")

    # ── Panel 2: Org1 (ORNL) introduces Alice ────────────────────────────────
    banner("PANEL 2 — Org1 (ORNL) signs Alice's cert via 'certified introduce'")

    # ORNL signs Alice's identity cert
    # Port lives in the *alias* URL (can_connect supplies it);
    # service URL must be bare host so replace_baseurl picks up the port.
    intro1_json = cli_run(["introduce", str(alice / "id.crt")], ornl)
    intro1 = json.loads(intro1_json)
    intro1["services"] = {"ornl-materials": "https://127.0.0.1"}
    intro1_path = tmp / "intro_ornl.json"
    intro1_path.write_text(json.dumps(intro1, indent=2))

    print("ORNL produced intro_ornl.json:")
    print_file(intro1_path, "intro_ornl.json")

    # Alice installs the introduction
    r = runner.invoke(app, [
        "add-intro", str(intro1_path), "--config", str(alice),
    ])
    assert r.exit_code == 0, f"add-intro failed: {r.stdout} {r.exception}"

    print("\nAlice's directory after Panel 2:")
    tree(alice)

    id_crt = next(alice.glob("id/*.crt"))
    print_file(id_crt, f"id/{id_crt.name}  (PEM chain signed by ORNL CA)")
    print_file(alice / "known_servers" / "ornl-materials.yaml")

    # The signed cert is issued by ORNL's CA, which is in ornl/known_clients/self.crt
    assert can_connect(alice, ornl, "ornl-materials", 18431), \
        "Alice should reach ORNL after introduction"
    print("\n✓  Alice can now connect to ORNL's API.")

    # ── Panel 3: Org2 (NIST) introduces Alice (asymmetric) ───────────────────
    banner("PANEL 3 — Org2 (NIST) signs Alice's cert (asymmetric cross-org trust)")

    intro2_json = cli_run(["introduce", str(alice / "id.crt")], nist)
    intro2 = json.loads(intro2_json)
    intro2["services"] = {"nist-cybersec": "https://127.0.0.1"}
    intro2_path = tmp / "intro_nist.json"
    intro2_path.write_text(json.dumps(intro2, indent=2))

    print("NIST produced intro_nist.json:")
    print_file(intro2_path, "intro_nist.json")

    r = runner.invoke(app, [
        "add-intro", str(intro2_path), "--config", str(alice),
    ])
    assert r.exit_code == 0, f"add-intro failed: {r.stdout} {r.exception}"

    print("\nAlice's directory after Panel 3 (two id/ chains, two known_servers/):")
    tree(alice)

    for crt in sorted((alice / "id").glob("*.crt")):
        print_file(crt, f"id/{crt.name}  (PEM chain)")
    print_file(alice / "known_servers" / "ornl-materials.yaml")
    print_file(alice / "known_servers" / "nist-cybersec.yaml")

    assert can_connect(alice, nist, "nist-cybersec", 18432), \
        "Alice should reach NIST after introduction"
    print("\n✓  Alice can now connect to both ORNL and NIST APIs.")
    print("✓  NIST gave Alice no reciprocal power — asymmetry is intentional.\n")

    banner("WALKTHROUGH COMPLETE — all assertions passed")


# ── pytest entry point ────────────────────────────────────────────────────────

def test_cross_chain(tmp_path: Path) -> None:
    run_walkthrough(tmp_path)


# ── standalone entry point ────────────────────────────────────────────────────

if __name__ == "__main__":
    with tempfile.TemporaryDirectory() as td:
        run_walkthrough(Path(td))
