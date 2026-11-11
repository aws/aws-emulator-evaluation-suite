"""composite-alarm-rule-cycle-and-unknown-child-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "composite-alarm-rule-cycle-and-unknown-child-rejected"
GROUP = 'alarms'
SERVICES = ['cloudwatch']


# ===== helpers =====
def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _assert_stays(probe, predicate, *, hold_s, interval_s, description):
    """Assert predicate(probe()) holds continuously for hold_s (bounded negative)."""
    deadline = time.monotonic() + hold_s
    while True:
        val = probe()
        assert predicate(val), f"{description} -- observed {val!r}"
        if time.monotonic() >= deadline:
            return val
        time.sleep(interval_s)


def _error(fn, why):
    """Call fn(); return the botocore Error dict of the refusal. An unexpected success raises
    AssertionError(why) so acceptance is not reported as a mere code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"{why}; the call SUCCEEDED and returned {result!r}")


def _swallow(fn):
    """Run a cleanup callable; only an already-deleted alarm (ResourceNotFound) is tolerated."""
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFound":
            raise
# ===== end helpers =====


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A composite AlarmRule over ALARM()/OK() derives correctly; unknown, self and malformed rules
    are refused; a cycle between existing alarms is accepted and inert; a referenced alarm cannot
    be deleted.

    Reference: https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_PutCompositeAlarm.html"""
    cw = ctx.client("cloudwatch")
    ns = ctx.unique_name("sim2real-behav-cwprobe-ns-composite-")
    leaf_a = ctx.unique_name("sim2real-behav-cwprobe-leafa-")
    leaf_b = ctx.unique_name("sim2real-behav-cwprobe-leafb-")
    comp = ctx.unique_name("sim2real-behav-cwprobe-comp-")
    comp2 = ctx.unique_name("sim2real-behav-cwprobe-comp2-")

    # The leaves' metric is never published; 'ignore' keeps each forced leaf state, so no
    # evaluation reclaims a leaf and moves the composite's derivation under the polls below.
    for leaf in (leaf_a, leaf_b):
        cw.put_metric_alarm(
            AlarmName=leaf,
            Namespace=ns,
            MetricName="Errors",
            Statistic="Sum",
            Period=60,
            EvaluationPeriods=1,
            Threshold=1.0,
            ComparisonOperator="GreaterThanThreshold",
            TreatMissingData="ignore",
            ActionsEnabled=False,
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )
    # Registered FIRST so LIFO teardown removes the composites before their children:
    # CloudWatch refuses to delete an alarm a composite rule still references.
    ctx.on_cleanup(lambda: _swallow(lambda: cw.delete_alarms(AlarmNames=[leaf_a, leaf_b])))

    rule = f'ALARM("{leaf_a}") AND OK("{leaf_b}")'
    cw.put_composite_alarm(
        AlarmName=comp, AlarmRule=rule, ActionsEnabled=False,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _swallow(lambda: cw.delete_alarms(AlarmNames=[comp])))

    def composite():
        found = cw.describe_alarms(AlarmNames=[comp], AlarmTypes=["CompositeAlarm"])["CompositeAlarms"]
        assert len(found) == 1, f"expected exactly one composite alarm named {comp}, got {found}"
        return found[0]

    created = composite()
    assert created["AlarmRule"] == rule, (
        f"the AlarmRule must round-trip verbatim (whitespace and quoting preserved), expected "
        f"{rule!r}, got {created['AlarmRule']!r}"
    )

    # --- Derivation: only ALARM(leafA) AND OK(leafB) yields ALARM ---
    cw.set_alarm_state(AlarmName=leaf_a, StateValue="ALARM", StateReason="probe: satisfy ALARM() clause")
    cw.set_alarm_state(AlarmName=leaf_b, StateValue="OK", StateReason="probe: satisfy OK() clause")
    got = _poll_until(
        composite,
        lambda c: c["StateValue"] == "ALARM",
        timeout_s=120,
        interval_s=3,
        description="the composite alarm to derive ALARM once both clauses hold",
    )
    assert got["StateReason"], "a derived composite state must carry a non-empty StateReason"

    # Falsify only the OK() clause: AND must now be false.
    cw.set_alarm_state(AlarmName=leaf_b, StateValue="ALARM", StateReason="probe: falsify OK() clause")
    _poll_until(
        composite,
        lambda c: c["StateValue"] == "OK",
        timeout_s=120,
        interval_s=3,
        description=(
            "the composite alarm to leave ALARM once OK(leafB) is false -- AND must be evaluated, "
            "not short-circuited on the first clause"
        ),
    )

    # Restore the ALARM condition for the control leg.
    cw.set_alarm_state(AlarmName=leaf_b, StateValue="OK", StateReason="probe: restore OK() clause")
    _poll_until(
        composite,
        lambda c: c["StateValue"] == "ALARM",
        timeout_s=120,
        interval_s=3,
        description="the composite alarm to return to ALARM once both clauses hold again",
    )

    # --- A child a composite rule names cannot be deleted out from under it ---
    # comp's rule still references leaf_a and leaf_b at this point, so this leg is not
    # vacuous. Break exactly one thing (delete a referenced leaf) -> specific refusal ->
    # the leaf is still there -> the composite still derives from it.
    error = _error(
        lambda: cw.delete_alarms(AlarmNames=[leaf_b]),
        f"{leaf_b} is named by {comp}'s rule, so deleting it would leave the composite with a "
        "dangling reference and must be refused",
    )
    assert error.get("Code") == "ValidationError", error
    assert error.get("Message") == (
        f"Cannot delete {leaf_b} as there are composite alarm(s) depending on it."
    ), (
        f"the refusal must name the dependency, got {error.get('Message')!r}"
    )
    assert len(cw.describe_alarms(AlarmNames=[leaf_b])["MetricAlarms"]) == 1, (
        f"the refused delete must not have removed {leaf_b}"
    )
    assert composite()["StateValue"] == "ALARM", (
        "the composite must still derive from the leaf the refused delete tried to remove"
    )

    # --- Negative 1: a self-referencing rule is rejected as an UNKNOWN CHILD ---
    # A composite cannot name itself for the same reason it cannot name a ghost: at
    # rule-validation time the alarm does not exist yet, so the reference does not resolve.
    self_ref = ctx.unique_name("sim2real-behav-cwprobe-comp-self-")
    error = _error(
        lambda: cw.put_composite_alarm(
            AlarmName=self_ref,
            AlarmRule=f'ALARM("{self_ref}")',
            ActionsEnabled=False,
        ),
        "a composite alarm whose rule references itself names an alarm that does not exist yet "
        "and must be rejected",
    )
    assert error.get("Code") == "ValidationError", error
    assert error.get("Message") == (
        "Could not save the composite alarm as alarms "
        f"[arn:aws:cloudwatch:{ctx.region}:{ctx.account}:alarm:{self_ref}] "
        "in the alarm rule do not exist"
    ), (
        "the refusal must attribute itself to the referenced alarm not existing (which is why a "
        f"1-cycle is refused at all) and name it, got {error.get('Message')!r}"
    )
    assert cw.describe_alarms(AlarmNames=[self_ref], AlarmTypes=["CompositeAlarm"])[
        "CompositeAlarms"
    ] == [], f"the rejected self-referencing rule must not have created {self_ref}"

    # --- A two-node cycle between EXISTING composites is ACCEPTED, and does not wedge ---
    # AlarmRule validation is existence + syntax; there is no cycle detection beyond the
    # 1-cycle that Negative 1 catches only incidentally. What matters is that the accepted
    # cycle is inert and that CloudWatch protects it from a dangling reference on delete.
    cw.put_composite_alarm(
        AlarmName=comp2, AlarmRule=f'ALARM("{leaf_b}")', ActionsEnabled=False,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _swallow(lambda: cw.delete_alarms(AlarmNames=[comp2])))
    cw.put_composite_alarm(AlarmName=comp2, AlarmRule=f'ALARM("{comp}")', ActionsEnabled=False)
    cycle_rule = f'ALARM("{comp2}")'
    cw.put_composite_alarm(AlarmName=comp, AlarmRule=cycle_rule, ActionsEnabled=False)
    # Registered immediately after the write it undoes: restoring comp's acyclic rule is what
    # makes the LIFO teardown below deletable at all (a live cycle is mutually undeletable).
    ctx.on_cleanup(
        lambda: _swallow(lambda: cw.put_composite_alarm(
            AlarmName=comp, AlarmRule=rule, ActionsEnabled=False
        ))
    )
    cycled = {
        c["AlarmName"]: c
        for c in cw.describe_alarms(
            AlarmNames=[comp, comp2], AlarmTypes=["CompositeAlarm"]
        )["CompositeAlarms"]
    }
    assert set(cycled) == {comp, comp2}, sorted(cycled)
    assert cycled[comp]["AlarmRule"] == cycle_rule, (
        f"the cyclic rule must be STORED, got {cycled[comp]['AlarmRule']!r}"
    )
    assert cycled[comp2]["AlarmRule"] == f'ALARM("{comp}")', cycled[comp2]["AlarmRule"]
    # Inert, not recursive: both ends of the cycle keep a resolvable StateValue, and keep it.
    _assert_stays(
        lambda: {
            c["AlarmName"]: c["StateValue"]
            for c in cw.describe_alarms(
                AlarmNames=[comp, comp2], AlarmTypes=["CompositeAlarm"]
            )["CompositeAlarms"]
        },
        lambda st: set(st) == {comp, comp2}
        and all(v in ("OK", "ALARM", "INSUFFICIENT_DATA") for v in st.values()),
        hold_s=20,
        interval_s=5,
        description=(
            "both ends of an accepted composite cycle must settle on a modelled StateValue "
            "rather than recursing or reporting nothing"
        ),
    )

    # Break exactly one thing: while comp2 -> comp is live, comp cannot be deleted. This is
    # the refusal that makes the accepted cycle safe.
    error = _error(
        lambda: cw.delete_alarms(AlarmNames=[comp]),
        f"{comp} is referenced by {comp2}'s rule, so deleting it would leave a dangling "
        "reference and must be refused",
    )
    assert error.get("Code") == "ValidationError", error
    assert error.get("Message") == (
        f"Cannot delete {comp} as there are composite alarm(s) depending on it."
    ), (
        f"the refusal must name the dependency, got {error.get('Message')!r}"
    )
    # Effect absent: the refused delete removed nothing.
    still_there = cw.describe_alarms(AlarmNames=[comp], AlarmTypes=["CompositeAlarm"])[
        "CompositeAlarms"
    ]
    assert len(still_there) == 1 and still_there[0]["AlarmRule"] == cycle_rule, still_there

    # --- Negative 3: a rule naming a child that does not exist ---
    ghost = ctx.unique_name("sim2real-behav-cwprobe-comp-ghost-")
    missing_child = ctx.unique_name("sim2real-behav-cwprobe-nonexistent-child-")
    error = _error(
        lambda: cw.put_composite_alarm(
            AlarmName=ghost,
            AlarmRule=f'ALARM("{missing_child}")',
            ActionsEnabled=False,
        ),
        f"a composite rule must only reference alarms that already exist; naming {missing_child} "
        "must be rejected rather than creating an alarm that can never resolve",
    )
    assert error.get("Code") == "ValidationError", error
    assert error.get("Message") == (
        "Could not save the composite alarm as alarms "
        f"[arn:aws:cloudwatch:{ctx.region}:{ctx.account}:alarm:{missing_child}] "
        "in the alarm rule do not exist"
    ), error.get("Message")
    assert cw.describe_alarms(AlarmNames=[ghost], AlarmTypes=["CompositeAlarm"])[
        "CompositeAlarms"
    ] == [], f"the rejected unknown-child rule must not have created {ghost}"

    # --- Negative 4: a syntactically malformed rule ---
    bad_syntax = ctx.unique_name("sim2real-behav-cwprobe-comp-syntax-")
    bad_rule_head = f'ALARM("{leaf_a}") AND '
    error = _error(
        lambda: cw.put_composite_alarm(
            AlarmName=bad_syntax,
            AlarmRule=f'{bad_rule_head}AND OK("{leaf_b}")',
            ActionsEnabled=False,
        ),
        "a malformed boolean rule must be rejected",
    )
    assert error.get("Code") == "ValidationError", error
    # A SYNTAX refusal, distinguished from the existence refusals above: same code, different
    # message shape. Without this an emulator could refuse everything with one message.
    assert error.get("Message") == (
        f"Error in AlarmRule [Unsupported token 'AND' at char {len(bad_rule_head)}, must be: "
        "'(', 'NOT', AT_LEAST, TRUE or FALSE, ALARM, OK, or INSUFFICIENT_DATA]"
    ), (
        f"a malformed rule must be refused as a PARSE failure, got {error.get('Message')!r}"
    )
    assert cw.describe_alarms(AlarmNames=[bad_syntax], AlarmTypes=["CompositeAlarm"])[
        "CompositeAlarms"
    ] == [], f"the rejected malformed rule must not have created {bad_syntax}"

    # --- Control: breaking the cycle restores the original rule and its derivation ---
    cw.put_composite_alarm(AlarmName=comp, AlarmRule=rule, ActionsEnabled=False)
    control = _poll_until(
        composite,
        lambda c: c["AlarmRule"] == rule and c["StateValue"] == "ALARM",
        timeout_s=120,
        interval_s=3,
        description=(
            "the composite to re-derive ALARM from its restored rule after every rejection"
        ),
    )
    assert control["AlarmRule"] == rule, control["AlarmRule"]
    assert control["StateValue"] == "ALARM", control["StateValue"]
    # comp2 was never the refused one -- comp was, because comp2's rule (still, at this
    # point, `ALARM("{comp}")`) is the live dependency. Deleting comp2 removes that sole
    # dependency, which is what actually frees comp below. Only ONE composite alarm may be
    # deleted per DeleteAlarms request, hence the single-element lists.
    cw.delete_alarms(AlarmNames=[comp2])
    assert cw.describe_alarms(AlarmNames=[comp2], AlarmTypes=["CompositeAlarm"])[
        "CompositeAlarms"
    ] == [], f"{comp2} must be deletable once nothing depends on it"

    # The identical call that was refused above (deleting comp) must now succeed, since its
    # sole dependent (comp2) is gone -- the refusal was about the live reference, not a
    # permanently wedged alarm.
    cw.delete_alarms(AlarmNames=[comp])
    assert cw.describe_alarms(AlarmNames=[comp], AlarmTypes=["CompositeAlarm"])[
        "CompositeAlarms"
    ] == [], f"{comp} must be deletable now that {comp2} no longer references it"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
