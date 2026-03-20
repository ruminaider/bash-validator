#!/usr/bin/env python3
"""Tests for inline code analyzers in bash-validator.py.

- is_safe_inline_python(): AST analysis for Python snippets
- is_safe_inline_js(): Regex analysis for Node.js snippets
- Integration: check_command() with inline code analysis
"""

import importlib.util
import os

import pytest

# Import bash-validator.py (hyphenated filename can't use normal import)
_spec = importlib.util.spec_from_file_location(
    "bash_validator",
    os.path.join(os.path.dirname(__file__), '..', 'hooks', 'bash-validator.py'),
)
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)

_is_safe_inline_python_raw = _mod.is_safe_inline_python
def is_safe_inline_python(code):
    safe, _reason = _is_safe_inline_python_raw(code)
    return safe
is_safe_inline_js = _mod.is_safe_inline_js
check_command = _mod.check_command


# ==============================================================================
# SAFE: inline Python that should be auto-approved
# ==============================================================================

class TestPythonASTSafe:
    """Python snippets that are safe data transforms — no I/O, no network."""

    @pytest.mark.parametrize("code", [
        # Pure JSON processing from stdin
        "import json, sys; print(json.dumps(json.load(sys.stdin), indent=2))",
        "import json,sys; data=json.load(sys.stdin); [print(f'#{d[\"number\"]} {d[\"title\"]}') for d in data]",
        "import sys, json\nfor line in sys.stdin:\n    d = json.loads(line)\n    print(d.get('name', '?'))",
        # CSV processing
        "import csv, sys, json; r=csv.DictReader(sys.stdin); print(json.dumps(list(r)))",
        # Simple operations
        "print('hello world')",
        "x = 2 + 2; print(x)",
        # Regex
        "import re; print(re.sub(r'\\s+', ' ', 'hello   world'))",
        # Collections
        "import collections; print(collections.Counter([1,2,2,3]))",
        # Datetime
        "import datetime; print(datetime.datetime.now().isoformat())",
        # sys I/O via stdin/stdout
        "import sys; data = sys.stdin.read(); sys.stdout.write(data)",
        # Base64
        "import base64, sys; print(base64.b64encode(sys.stdin.buffer.read()).decode())",
        # Hashlib
        "import hashlib, sys; print(hashlib.sha256(sys.stdin.buffer.read()).hexdigest())",
    ])
    def test_safe_python(self, code):
        assert is_safe_inline_python(code) is True, f"Expected SAFE: {code!r}"


# ==============================================================================
# DANGEROUS: inline Python that should prompt the user
# ==============================================================================

class TestPythonASTDangerous:
    """Python snippets that touch the filesystem, network, or execute code."""

    @pytest.mark.parametrize("code", [
        # File I/O
        "open('/etc/passwd').read()",
        "f = open('out.txt', 'w'); f.write('data')",
        "with open('file.txt') as f: print(f.read())",
        # OS
        "import os; os.system('rm -rf /')",
        "import os; os.remove('file.txt')",
        "import os; print(os.listdir('/'))",
        # Subprocess
        "import subprocess; subprocess.run(['ls'])",
        "from subprocess import call; call(['rm', '-rf', '/'])",
        # Network
        "import urllib.request; urllib.request.urlopen('http://evil.com')",
        "import socket; s = socket.socket()",
        "import http.client; http.client.HTTPConnection('evil.com')",
        # Code execution
        "exec('import os; os.system(\"rm -rf /\")')",
        "eval('__import__(\"os\").system(\"rm -rf /\")')",
        "compile('print(1)', '<string>', 'exec')",
        "__import__('os').system('ls')",
        # Dynamic import
        "import importlib; importlib.import_module('os')",
        # Evasion via getattr
        "import os; getattr(os, 'system')('ls')",
        # Dangerous sys usage
        "import sys; sys.exit(1)",
        # shutil
        "import shutil; shutil.rmtree('/tmp/dir')",
        # pathlib
        "import pathlib; pathlib.Path('file.txt').write_text('data')",
        # tempfile
        "import tempfile; tempfile.mktemp()",
        # ctypes
        "import ctypes; ctypes.cdll.LoadLibrary('libc.so')",
        # pickle
        "import pickle, sys; pickle.load(sys.stdin.buffer)",
        # multiprocessing
        "import multiprocessing; multiprocessing.Process(target=print).start()",
        # webbrowser
        "import webbrowser; webbrowser.open('http://evil.com')",
        # Dunder access
        "print.__class__.__bases__[0].__subclasses__()",
        # __builtins__ subscript access bypass
        '__builtins__["open"]("/etc/passwd")',
        '__builtins__.__getitem__("open")',
        # Syntax error
        "this is not valid python {{{{",
    ])
    def test_dangerous_python(self, code):
        assert is_safe_inline_python(code) is False, f"Expected DANGEROUS: {code!r}"


# ==============================================================================
# SAFE: inline Node.js that should be auto-approved
# ==============================================================================

class TestNodeJSSafe:
    """Node.js snippets that are safe data transforms — no I/O, no network."""

    @pytest.mark.parametrize("code", [
        "console.log('hello')",
        "console.log(JSON.stringify({a: 1}, null, 2))",
        "const path = require('node:path'); console.log(path.resolve('.', 'src'))",
        "const x = [1,2,3].map(n => n * 2); console.log(x)",
        "console.log(Array.from({length: 10}, (_, i) => i))",
        "const {resolve, join} = require('node:path'); console.log(resolve('.', 'src'))",
        "console.log('hello world'.replace(/\\s+/g, '-'))",
        "console.log(Buffer.from('hello').toString('base64'))",
        "console.log(Math.max(1, 2, 3))",
        "const u = new URL('http://example.com/path'); console.log(u.hostname)",
    ])
    def test_safe_js(self, code):
        assert is_safe_inline_js(code) is True, f"Expected SAFE: {code!r}"


# ==============================================================================
# DANGEROUS: inline Node.js that should prompt the user
# ==============================================================================

class TestNodeJSDangerous:
    """Node.js snippets that touch the filesystem, network, or execute code."""

    @pytest.mark.parametrize("code", [
        "const fs = require('fs'); fs.readFileSync('/etc/passwd')",
        "require('fs').writeFileSync('out.txt', 'data')",
        "const {readFileSync} = require('fs'); readFileSync('file')",
        "require('node:fs').unlinkSync('file')",
        "require('child_process').execSync('rm -rf /')",
        "const {spawnSync} = require('child_process'); spawnSync('ls')",
        "require('http').createServer()",
        "require('https').get('http://evil.com')",
        "fetch('http://evil.com')",
        "eval('process.exit(1)')",
        "new Function('return process.exit()')",
        "process.exit(1)",
        "process.kill(process.pid)",
        "require('vm').runInNewContext('1+1')",
        "const m = 'fs'; require(m)",
        "require('net').createServer()",
        "require('dgram').createSocket('udp4')",
        # OS module
        "require('os').homedir()",
        # fs/promises subpath
        "const fs = require('fs/promises'); fs.readFile('secret.txt')",
        # Template literal require
        "require(`fs`)",
        # Dynamic ESM import
        "import('fs').then(fs => fs.readFile('x'))",
    ])
    def test_dangerous_js(self, code):
        assert is_safe_inline_js(code) is False, f"Expected DANGEROUS: {code!r}"


# ==============================================================================
# INTEGRATION: check_command() with inline code analysis
# ==============================================================================

class TestInlineCodeIntegration:
    """End-to-end: check_command() correctly routes inline code to analyzers."""

    # --- Safe inline commands (should auto-approve) ---
    @pytest.mark.parametrize("cmd", [
        'python3 -c "import json, sys; print(json.dumps(json.load(sys.stdin), indent=2))"',
        "python3 -c 'import sys; [print(line.strip()) for line in sys.stdin]'",
        'echo \'{"a":1}\' | python3 -c "import json,sys; print(json.dumps(json.load(sys.stdin)))"',
        'gh issue list --json number,title | python3 -c "import json,sys; data=json.load(sys.stdin); [print(d[\'title\']) for d in data]"',
        "node -e \"console.log(JSON.stringify({a: 1}, null, 2))\"",
        "node -e \"const x = [1,2,3].map(n => n*2); console.log(x)\"",
    ])
    def test_safe_inline_commands(self, cmd):
        assert check_command(cmd) is True, f"Expected SAFE: {cmd!r}"

    # --- Dangerous inline commands (should prompt) ---
    @pytest.mark.parametrize("cmd", [
        'python3 -c "open(\'/etc/passwd\').read()"',
        'python3 -c "import os; os.system(\'ls\')"',
        'python3 -c "import subprocess; subprocess.run([\'ls\'])"',
        "node -e \"require('fs').readFileSync('/etc/passwd')\"",
        "node -e \"require('child_process').execSync('ls')\"",
        "ruby -e 'puts 1'",
        "deno eval 'console.log(1)'",
    ])
    def test_dangerous_inline_commands(self, cmd):
        assert check_command(cmd) is False, f"Expected DANGEROUS: {cmd!r}"

    # --- Edge cases ---
    def test_python_c_no_code(self):
        """python3 -c with no code after flag → deny."""
        assert check_command("python3 -c") is False

    def test_python_script_file(self):
        """python3 running a script file (no -c) → allow."""
        assert check_command("python3 script.py") is True

    def test_node_script_file(self):
        """node running a script file (no -e) → allow."""
        assert check_command("node app.js") is True
