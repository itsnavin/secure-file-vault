"""Exercise exact public guide snippets in Linux pseudo-terminals; never user secrets."""
import errno
from html.parser import HTMLParser
import os
from pathlib import Path
import pty
import re
import select
import signal
import stat
import subprocess
import tempfile
import time


class Commands(HTMLParser):
    def __init__(self):
        super().__init__()
        self.commands = {}
        self.current = None

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        if tag == "code" and attributes.get("id", "").endswith("-command"):
            self.current = attributes["id"]
            self.commands[self.current] = ""

    def handle_endtag(self, tag):
        if tag == "code":
            self.current = None

    def handle_data(self, data):
        if self.current:
            self.commands[self.current] += data


def terminal(command, cwd, password="PUBLIC synthetic CLI test only"):
    """Run the unmodified command with a controlling terminal and answer its prompts."""
    pid, fd = pty.fork()
    if pid == 0:
        os.chdir(cwd)
        os.umask(0o077)
        os.execv("/bin/bash", ["bash", "--noprofile", "--norc", "-c", command])
    output = bytearray()
    cursor = 0
    prompts = 0
    exit_status = None
    deadline = time.monotonic() + 30
    try:
        while True:
            if time.monotonic() > deadline:
                raise TimeoutError("Public guide command timed out")
            if select.select([fd], [], [], 0.05)[0]:
                try:
                    chunk = os.read(fd, 65536)
                except OSError as error:
                    if error.errno == errno.EIO:
                        break
                    raise
                if not chunk:
                    break
                output.extend(chunk)
                while match := re.search(rb"password:", output[cursor:], re.IGNORECASE):
                    cursor += match.end()
                    prompts += 1
                    if prompts > 2:
                        raise AssertionError("Unexpected extra password prompt")
                    os.write(fd, password.encode("utf-8") + b"\n")
            completed, status = os.waitpid(pid, os.WNOHANG)
            if completed:
                exit_status = status
                # Drain any terminal output after the process has exited.
                while select.select([fd], [], [], 0)[0]:
                    try:
                        chunk = os.read(fd, 65536)
                    except OSError as error:
                        if error.errno == errno.EIO:
                            break
                        raise
                    if not chunk:
                        break
                    output.extend(chunk)
                break
        if exit_status is None:
            _, exit_status = os.waitpid(pid, 0)
        return os.waitstatus_to_exitcode(exit_status), bytes(output), prompts
    finally:
        if exit_status is None:
            # Only the bounded test child created above can be terminated here.
            try:
                os.kill(pid, signal.SIGKILL)
                os.waitpid(pid, 0)
            except ProcessLookupError:
                pass
        os.close(fd)


def require_success(command, cwd, expected_prompts=0):
    code, output, prompts = terminal(command, cwd)
    assert code == 0, output.decode("utf-8", errors="replace")
    assert prompts == expected_prompts, f"Expected {expected_prompts} prompts, got {prompts}"
    return output


def main():
    root = Path(__file__).resolve().parents[1]
    parser = Commands()
    parser.feed((root / "linux.html").read_text(encoding="utf-8"))
    commands = parser.commands
    version = subprocess.check_output(["openssl", "version"], text=True).strip()
    assert re.match(r"OpenSSL 3\.", version), f"Test requires OpenSSL 3.x: {version}"
    print(f"Exact public guide commands tested on Linux: {version}", flush=True)

    with tempfile.TemporaryDirectory(prefix="sfv-guide-tests-") as directory:
        base = Path(directory)
        # Run the actual setup block in a temporary parent, without leaving a demo directory.
        setup_output = require_success(commands["setup-command"], base)
        demo = Path(setup_output.decode().strip())
        try:
            assert demo.name.startswith("file-vault-demo.")
            assert stat.S_IMODE(demo.stat().st_mode) == 0o700
            require_success(commands["version-command"], demo)
            require_success(commands["sample-command"], demo)
            original = (demo / "original.bin").read_bytes()
            require_success(commands["encrypt-command"], demo, 2)
            encrypted = (demo / "original.bin.enc").read_bytes()
            assert encrypted.startswith(b"Salted__")
            require_success(commands["decrypt-command"], demo, 1)
            assert (demo / "recovered.bin").read_bytes() == original
            require_success(commands["compare-command"], demo)
            require_success(commands["base64-encrypt-command"], demo, 2)
            require_success(commands["base64-decrypt-command"], demo, 1)
            assert (demo / "recovered-base64.bin").read_bytes() == original
            for path in demo.iterdir():
                assert stat.S_IMODE(path.stat().st_mode) == 0o600, path.name
        finally:
            # Cleanup only the specific practice files and directory this test just created.
            for name in ["original.bin", "original.bin.enc", "recovered.bin",
                         "original.bin.enc.b64", "recovered-base64.bin"]:
                (demo / name).unlink(missing_ok=True)
            demo.rmdir()
        print("PASS: all 8 displayed snippets, interactive prompts, binary/Base64 bytes, private permissions", flush=True)

        # Include all byte values and a long payload so failure can visibly leave partial output.
        binary = bytes(range(256)) * 16
        (base / "original.bin").write_bytes(binary)
        require_success(commands["encrypt-command"], base, 2)
        require_success(commands["decrypt-command"], base, 1)
        assert (base / "recovered.bin").read_bytes() == binary
        sealed = (base / "original.bin.enc").read_bytes()
        # The documented 3.0/3.5 default salted layout has an 8-byte marker and 8-byte salt.
        assert len(sealed) == 16 + len(binary) + 16
        modified = bytearray(sealed)
        modified[16] ^= 1  # First ciphertext block, not the final padding block.
        (base / "original.bin.enc").write_bytes(modified)
        require_success(commands["decrypt-command"], base, 1)
        assert (base / "recovered.bin").read_bytes() != binary
        print("PASS: modified CBC ciphertext decrypts with status 0 but changed bytes (NO authentication)", flush=True)

        (base / "original.bin.enc").write_bytes(sealed)
        # Padding can accept a wrong password by chance. Observe failure without asserting
        # that every incorrect password necessarily fails (which would be a false guarantee).
        for attempt in range(8):
            code, _, prompts = terminal(commands["decrypt-command"], base,
                                         f"PUBLIC incorrect synthetic password {attempt}")
            assert prompts == 1
            if code != 0:
                assert (base / "recovered.bin").stat().st_size > 0
                print("PASS: observed wrong-password failure with partial/garbage output; "
                      "failure is NOT guaranteed for all wrong passwords", flush=True)
                break
        else:
            raise AssertionError("Could not observe the documented wrong-password failure")
    print("All Linux/OpenSSL guide checks passed. Public test files cleaned up.", flush=True)


if __name__ == "__main__":
    main()
