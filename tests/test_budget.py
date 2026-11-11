"""A test's emulator budget: 600 s for timing:real-time or a slow tool its own require_tools(...)
calls name (cdk, terraform, tofu, docker), else 60 s; an explicit budget wins."""

import pytest

from fidelity_tests_runner import VERDICT_PASSED, run_check, tags
from fidelity_tests_runner.budget import (
    EMULATOR_BUDGET_S,
    EMULATOR_MAX_BUDGET_S,
    REAL_TIME_TAG,
    SLOW_TOOLS,
    check_budget,
    exceeds_emulator_cap,
    required_tools,
    stated_period_s,
)
from fidelity_tests_runner.context import FIXED_CREDS, Context
from fidelity_tests_runner.run import load_check


def test_the_budgets_are_pinned():
    assert (EMULATOR_BUDGET_S, EMULATOR_MAX_BUDGET_S) == (60.0, 600.0)
    assert REAL_TIME_TAG == "timing:real-time"
    assert frozenset({"cdk", "terraform", "tofu", "docker"}) == SLOW_TOOLS


@pytest.mark.parametrize(
    ("check_tags", "tools", "budget"),
    [
        ((), (), 60.0),
        (("axis:happy-path",), (), 60.0),
        (("timing:real-time",), (), 600.0),
        (("timing:long",), (), 60.0),
        (("timing:over-budget",), (), 60.0),
        ((), ("aws", "openssl"), 60.0),
        ((), ("cdk", "node"), 600.0),
        ((), ("terraform",), 600.0),
        ((), ("tofu",), 600.0),
        ((), ("docker", "aws"), 600.0),
    ],
)
def test_the_budget_follows_the_timing_tag_and_the_tools(check_tags, tools, budget):
    assert check_budget(check_tags, tools=tools) == budget


def test_an_explicit_budget_wins():
    assert check_budget(("timing:real-time",), explicit=30, tools=("cdk",)) == 30.0
    with pytest.raises(ValueError):
        check_budget((), explicit=0)


def test_required_tools_reads_every_require_tools_call_statically():
    source = (
        "from fidelity_tests_runner import require_tools\n"
        "import fidelity_tests_runner as h\n"
        "def run(ctx):\n"
        '    require_tools("cdk", "node")\n'
        '    h.require_tools("docker")\n'
        "    require_tools(*names)\n"
    )
    assert required_tools(source) == {"cdk", "node", "docker"}
    assert required_tools("def (") == frozenset()


def test_run_check_gives_a_real_time_test_the_long_budget():
    @tags("timing:real-time")
    def run(ctx):
        pass

    result = run_check(
        lambda: Context("http://127.0.0.1:4566", creds=dict(FIXED_CREDS)), "rt", "g", run
    )
    assert result.verdict == VERDICT_PASSED
    assert result.budget_s == EMULATOR_MAX_BUDGET_S


@pytest.mark.parametrize(("tool", "budget"), [("terraform", 600.0), ("openssl", 60.0)])
def test_run_check_reads_the_tools_from_the_test_file(tmp_path, tool, budget):
    path = tmp_path / "check_x.py"
    path.write_text(
        "def run(ctx):\n"
        "    return None\n"
        "def _unused():\n"
        "    from fidelity_tests_runner import require_tools\n"
        f'    require_tools("{tool}")\n'
    )
    check = load_check(path)
    result = run_check(
        lambda: Context("http://127.0.0.1:4566", creds=dict(FIXED_CREDS)), "x", "g", check.run
    )
    assert result.verdict == VERDICT_PASSED
    assert result.budget_s == budget


@pytest.mark.parametrize(
    ("check_tags", "period_s", "aws_s", "expected"),
    [
        (("timing:real-time",), 540.0, None, False),
        (("timing:real-time",), 541.0, None, True),
        (("timing:real-time",), 60.0, 3546.0, False),
        (("timing:real-time",), 600.0, None, True),
        (("timing:real-time",), 600.0, 120.0, True),
        (("timing:real-time",), None, 540.0, False),
        (("timing:real-time",), None, 540.5, True),
        (("timing:real-time",), None, None, False),
        ((), 900.0, None, False),
    ],
)
def test_a_real_time_test_exceeds_the_cap_by_the_period_it_states(
    check_tags, period_s, aws_s, expected
):
    assert exceeds_emulator_cap(check_tags, period_s, aws_s) is expected


@pytest.mark.parametrize(
    ("source", "period"),
    [
        ("# timing:real-time — ttl: 300 s https://docs.aws.amazon.com/x\n@tags()\n", 300.0),
        ("# timing:real-time — bogus: 300 s\n", None),
        ("# timing:real-time - ttl: 300 s\n", None),
        ("x = 1\n", None),
    ],
)
def test_stated_period_reads_the_justification_line(source, period):
    assert stated_period_s(source) == period
