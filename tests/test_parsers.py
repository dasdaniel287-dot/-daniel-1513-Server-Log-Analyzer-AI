"""
Unit Tests for Modular Log Parsers
"""

from app.parsers.auth import parse_auth_line
from app.parsers.nginx import parse_nginx_access, parse_nginx_error
from app.parsers.json_logs import parse_json_line
from app.parsers.syslog import parse_syslog_line


def test_ssh_auth_parser_failed():
    line = "Oct 25 14:02:11 bastion sshd[28410]: Failed password for invalid user admin from 198.51.100.42 port 49212 ssh2"
    entry = parse_auth_line(line, 1)
    assert entry is not None
    assert entry["source"] == "auth"
    assert entry["level"] == "WARN"
    assert entry["ip"] == "198.51.100.42"
    assert entry["auth"]["user"] == "admin"
    assert entry["auth"]["status"] == "FAILURE"


def test_ssh_auth_parser_accepted():
    line = "Oct 25 14:02:45 bastion sshd[28435]: Accepted password for ubuntu from 198.51.100.42 port 49248 ssh2"
    entry = parse_auth_line(line, 2)
    assert entry is not None
    assert entry["level"] == "INFO"
    assert entry["auth"]["user"] == "ubuntu"
    assert entry["auth"]["status"] == "SUCCESS"


def test_nginx_access_parser():
    line = '198.51.100.15 - - [25/Oct/2026:14:10:06 +0000] "GET /.env HTTP/1.1" 404 162 "-" "Mozilla/5.0"'
    entry = parse_nginx_access(line, 3)
    assert entry is not None
    assert entry["source"] == "nginx_access"
    assert entry["http"]["status"] == 404
    assert entry["http"]["path"] == "/.env"
    assert entry["ip"] == "198.51.100.15"


def test_json_log_parser():
    line = '{"timestamp":"2026-10-25T14:30:00Z","level":"ERROR","service":"auth-svc","message":"Token expired","ip":"10.0.0.1"}'
    entry = parse_json_line(line, 4)
    assert entry is not None
    assert entry["source"] == "json"
    assert entry["level"] == "ERROR"
    assert entry["service"] == "auth-svc"
    assert entry["ip"] == "10.0.0.1"


def test_syslog_parser():
    line = "Oct 25 14:16:35 app-node-03 kernel: [ 4215.112] Out of memory: Kill process 3912 (python3) score 892"
    entry = parse_syslog_line(line, 5)
    assert entry is not None
    assert entry["source"] == "syslog"
    assert entry["level"] == "CRITICAL"
    assert entry["service"] == "kernel"
