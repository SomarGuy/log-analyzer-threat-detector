from datetime import datetime
from pathlib import Path

import pytest

from loganalyzer import synthetic
from loganalyzer.cli import load_events
from loganalyzer.engine import analyze
from loganalyzer.models import Event
from loganalyzer.report import build_report
from loganalyzer.rules import DEFAULT_RULES_PATH, load_rules


@pytest.fixture(scope="session")
def rules():
    return load_rules(DEFAULT_RULES_PATH)


@pytest.fixture(scope="session")
def rule_by_id(rules):
    return {r.id: r for r in rules}


@pytest.fixture(scope="session")
def synth_dir(tmp_path_factory):
    d = tmp_path_factory.mktemp("synthetic")
    synthetic.generate(d, seed=1337)
    return d


@pytest.fixture(scope="session")
def synth_result(synth_dir, rules):
    events, stats = load_events([str(synth_dir / "auth.log")],
                                [str(synth_dir / "windows_security_dc01.csv"), str(synth_dir / "windows_security_ws12.json")],
                                [str(synth_dir / "access.log")], year=2026, web_host=synthetic.WEB_HOST)
    return analyze(events, rules, stats)


@pytest.fixture(scope="session")
def synth_report(synth_result):
    return build_report(synth_result, synthetic=True, generated_at=datetime(2026, 10, 18, 9, 0, 0))


def T(day=13, h=2, m=0, s=0):
    return datetime(2026, 10, day, h, m, s)


def ev(kind, source="auth", ts=None, **kw):
    """Quick Event factory for detector tests."""
    extra = kw.pop("extra", {})
    return Event(ts=ts or T(), source=source, kind=kind, raw=kw.pop("raw", "raw line"), extra=extra, **kw)
