"""Pass marks for the rules half (written before the first run): unknown tools blocked; paths cannot escape the allowed
folder with ../ or backslashes; only listed websites; forbidden command patterns blocked; 'ask' tools need approval;
rate and spending caps hold; the kill switch stops everything; after a suspected injection, data-moving tools need approval;
every decision lands in the audit log."""
import json

import pytest

from blue_guardian.detect import Detection
from blue_guardian.evaluate import evaluate
from blue_guardian.gateway import Blocked, Guardian
from blue_guardian.policy import Policy

POLICY = {
    "tools": {
        "read_file": {"paths": ["./workspace/**"]},
        "write_file": {"paths": ["./workspace/**"], "ask": True},
        "http_get": {"domains": ["api.github.com", "*.wikipedia.org"]},
        "shell": {"deny": [r"rm\s+-rf"]},
        "send_email": {"allow": False},
    },
    "limits": {"actions_per_minute": 5, "usd_per_day": 1.0},
}


class FlagEverything:
    """Stands in for a detector that has flagged the text as an injection."""
    name = "flag-all"

    def score(self, text):
        return Detection(0.99, True, ["test"])


class FlagNothing:
    name = "flag-none"

    def score(self, text):
        return Detection(0.01, False, [])


def test_paths_domains_and_switches():
    p = Policy.load(POLICY)
    assert p.check("read_file", {"path": "workspace/notes.txt"}).allowed
    assert p.check("read_file", {"path": "./workspace/sub/a.md"}).allowed
    for bad in ("workspace/../.env", "..\\secrets.txt", "/etc/passwd", "workspace/../../home/me/.ssh/id_rsa"):
        assert p.check("read_file", {"path": bad}).verdict == "block", bad
    assert p.check("http_get", {"url": "https://en.wikipedia.org/wiki/Sparta"}).allowed
    assert p.check("http_get", {"url": "https://api.github.com.evil.example/x"}).verdict == "block"
    assert p.check("shell", {"cmd": "ls -la"}).allowed
    assert p.check("shell", {"cmd": "rm  -rf /"}).verdict == "block"
    assert p.check("send_email", {"to": "a@b.c"}).verdict == "block"
    assert p.check("delete_database", {}).verdict == "block"                   # not in the policy
    assert p.check("write_file", {"path": "workspace/out.txt"}).verdict == "ask"


def test_rate_and_spend_caps():
    p = Policy.load(POLICY)
    for i in range(5):
        assert p.check("shell", {"cmd": "echo hi"}, now=100 + i).allowed
    assert "minute" in p.check("shell", {"cmd": "echo hi"}, now=106).reason
    assert p.check("shell", {"cmd": "echo hi"}, now=200).allowed               # a minute later it is fine again
    q = Policy.load(POLICY)
    assert q.check("shell", {"cmd": "x"}, cost_usd=0.8, now=0).allowed
    assert "spending cap" in q.check("shell", {"cmd": "x"}, cost_usd=0.3, now=10).reason


def test_taint_kill_switch_and_audit(tmp_path):
    log = tmp_path / "audit.jsonl"
    g = Guardian(POLICY, detector=FlagEverything(), audit_log=str(log), kill_switch=str(tmp_path / "STOP"))
    assert g.authorize("http_get", {"url": "https://api.github.com/repos"}).verdict == "allow"
    g.inspect("text from a web page", source="web")                             # flagged: the session is now tainted
    d = g.authorize("http_get", {"url": "https://api.github.com/repos"})
    assert d.verdict == "ask" and d.rule == "taint"
    assert g.authorize("read_file", {"path": "workspace/a"}).verdict == "allow"  # reading is not moving data out
    (tmp_path / "STOP").write_text("")
    assert g.authorize("read_file", {"path": "workspace/a"}).rule == "kill_switch"
    lines = [json.loads(x) for x in log.read_text().splitlines()]
    assert [x["kind"] for x in lines].count("authorize") == 4 and any(x["kind"] == "inspect" for x in lines)


def test_user_text_does_not_taint():
    g = Guardian(POLICY, detector=FlagEverything())
    g.inspect("something the owner typed", source="user")
    assert g.authorize("http_get", {"url": "https://api.github.com/x"}).allowed


def test_guard_decorator():
    g = Guardian(POLICY, detector=FlagNothing())
    sent = []
    read = g.guard("read_file")(lambda path: f"contents of {path}")
    write = g.guard("write_file", approve=lambda tool, args, d: args["path"].endswith(".txt"))(lambda path: sent.append(path))
    assert read(path="workspace/a.md") == "contents of workspace/a.md"
    with pytest.raises(Blocked):
        read(path="workspace/../.env")
    write(path="workspace/ok.txt")
    with pytest.raises(Blocked):
        write(path="workspace/no.sh")                                           # approver said no
    assert sent == ["workspace/ok.txt"]


def test_evaluate_metrics():
    data = [{"text": "a", "label": 1}, {"text": "b", "label": 1}, {"text": "c", "label": 0}, {"text": "d", "label": 0}]
    r = evaluate(FlagEverything(), data)
    assert r["catch_rate"] == 1.0 and r["false_alarm_rate"] == 1.0
    r = evaluate(FlagNothing(), data)
    assert r["catch_rate"] == 0.0 and r["false_alarm_rate"] == 0.0
