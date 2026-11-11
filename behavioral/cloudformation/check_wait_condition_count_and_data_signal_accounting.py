"""wait-condition-count-and-data-signal-accounting."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _routed_request(ctx, url, data=None, headers=None, **kwargs):
    """A urllib Request that reaches ``url`` on the target, with ``ctx.endpoint_route``'s headers."""
    target, route = ctx.endpoint_route(url)
    return urllib.request.Request(target, data=data, headers={**(headers or {}), **route}, **kwargs)


CHECK = "wait-condition-count-and-data-signal-accounting"
GROUP = "server-side"
SERVICES = ["cloudformation"]

#: The twin control is a Count=1 wait condition signalled in the same instant as the Count=2
#: subject: a target with no signal path at all fails the control leg, and a target
#: that completes on the first signal regardless of Count fails the freeze legs.
CONTROL_TIMEOUT_S = 150.0
#: Consecutive identical reads for the freeze detector. Spaced FREEZE_INTERVAL_S apart, so
#: this is also >= 15s of margin past the control's own completion.
FREEZE_READS = 3
FREEZE_INTERVAL_S = 5.0
_TERMINAL = {
    "CREATE_COMPLETE",
    "CREATE_FAILED",
    "ROLLBACK_IN_PROGRESS",
    "ROLLBACK_COMPLETE",
    "ROLLBACK_FAILED",
    "DELETE_IN_PROGRESS",
    "DELETE_COMPLETE",
}


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A Count=N wait condition must require N *distinct* UniqueIds, and GetAtt Data must be the
    exact UniqueId->Data map of the signals that counted."""
    cf = ctx.client("cloudformation")
    tag = [{"Key": "sim2real-check", "Value": CHECK}]

    subject = ctx.unique_name("sim2real-wc-count2-")
    control = ctx.unique_name("sim2real-wc-count1-")
    cf.create_stack(StackName=subject, TemplateBody=_template(count=2), Tags=tag)
    ctx.on_cleanup(lambda: cf.delete_stack(StackName=subject))
    cf.create_stack(StackName=control, TemplateBody=_template(count=1), Tags=tag)
    ctx.on_cleanup(lambda: cf.delete_stack(StackName=control))

    subject_url = _handle_url(cf, subject, timeout_s=120.0)
    control_url = _handle_url(cf, control, timeout_s=120.0)

    # Runtime-generated ids: the Data map below can only be right if the target actually stored
    # what this process PUT.
    uid1, data1 = ctx.unique_name("uid1-"), ctx.unique_name("payload1-")
    uid2, data2 = ctx.unique_name("uid2-"), ctx.unique_name("payload2-")
    uid_c, data_c = ctx.unique_name("uidc-"), ctx.unique_name("payloadc-")

    # --- Beat 1: one signal each, in the same instant -------------------------------------------
    _signal(ctx, subject_url, uid1, data1, timeout_s=60.0)
    _signal(ctx, control_url, uid_c, data_c, timeout_s=60.0)

    # --- Beat 2: the control (Count=1) must complete -> the signal path demonstrably works ------
    control_status = _poll_status(
        cf, control, lambda s: s in _TERMINAL, timeout_s=CONTROL_TIMEOUT_S,
        why="the Count=1 control must complete on its single signal",
    )
    assert control_status == "CREATE_COMPLETE", (
        f"control stack {control!r}: expected CREATE_COMPLETE after one signal to a Count=1 wait "
        f"condition, got {control_status!r}; without this leg the freeze legs below would pass "
        "against a target that has no signal path at all"
    )
    control_data = json.loads(_output(cf, control, "WaitData"))
    assert control_data == {uid_c: data_c}, (
        f"control GetAtt Data: expected exactly {{{uid_c!r}: {data_c!r}}}, got {control_data!r}"
    )

    # --- Beat 3: the subject (Count=2) must NOT have advanced on one signal ---------------------
    _assert_frozen_in_progress(cf, subject, "one of two signals delivered")

    # --- Beat 4: repeating the SAME UniqueId must not count as the second signal ----------------
    # Identical payload, so the expected Data map is unambiguous under either duplicate policy
    # (ignore or overwrite) — the subject here is the COUNT, not which Data wins.
    _signal(ctx, subject_url, uid1, data1, timeout_s=60.0)
    _assert_frozen_in_progress(cf, subject, "the second signal reused UniqueId " + uid1)

    # --- Beat 5: a second DISTINCT UniqueId must complete it ------------------------------------
    _signal(ctx, subject_url, uid2, data2, timeout_s=60.0)
    subject_status = _poll_status(
        cf, subject, lambda s: s in _TERMINAL, timeout_s=CONTROL_TIMEOUT_S,
        why="two distinct signals must satisfy Count=2",
    )
    assert subject_status == "CREATE_COMPLETE", (
        f"subject stack {subject!r}: expected CREATE_COMPLETE once two DISTINCT UniqueIds were "
        f"signalled, got {subject_status!r}; a target that withholds completion after the required "
        "count is as wrong as one that completes early"
    )

    # --- Beat 6: terminal read at the destination, through a different operation ----------------
    # DescribeStacks Outputs, not the PUT response and not a status word: the Data attribute is
    # the only place the target can be caught inventing or losing signals.
    subject_data = json.loads(_output(cf, subject, "WaitData"))
    assert subject_data == {uid1: data1, uid2: data2}, (
        f"subject GetAtt Data: expected exactly {{{uid1!r}: {data1!r}, {uid2!r}: {data2!r}}} "
        f"(2 keys, the counted signals), got {subject_data!r}"
    )


# ===== helpers =====


def _template(*, count: int) -> str:
    """A WaitConditionHandle + WaitCondition(Count=count) exposing GetAtt Data as an Output.

    Timeout is a string per the WaitCondition contract, and long enough that nothing in this check
    can be explained by the timeout firing.
    """
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Handle": {"Type": "AWS::CloudFormation::WaitConditionHandle"},
                "Wait": {
                    "Type": "AWS::CloudFormation::WaitCondition",
                    "Properties": {"Handle": {"Ref": "Handle"}, "Timeout": "900", "Count": count},
                },
            },
            "Outputs": {"WaitData": {"Value": {"Fn::GetAtt": ["Wait", "Data"]}}},
        }
    )


def _handle_url(cf, stack_name: str, *, timeout_s: float) -> str:
    """The handle's presigned PUT URL is its PhysicalResourceId; it appears once the resource is
    created, which is asynchronous, so this is a bounded retry that RAISES on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            detail = cf.describe_stack_resource(StackName=stack_name, LogicalResourceId="Handle")
            url = detail["StackResourceDetail"].get("PhysicalResourceId")
            if url:
                return url
            last = detail["StackResourceDetail"].get("ResourceStatus")
        except ClientError as exc:
            last = exc.response.get("Error", {}).get("Code")
        time.sleep(2.0)
    raise AssertionError(
        f"WaitConditionHandle URL for {stack_name!r} not available within {timeout_s}s (last={last!r})"
    )


def _signal(ctx, handle_url: str, unique_id: str, data: str, *, timeout_s: float) -> None:
    """PUT the documented wait-condition signal JSON to the presigned URL.

    Bounded retry with a deadline: the presigned URL is an S3 object PUT and can 503/throttle. The
    request method must be PUT and Content-Type must be empty per the signal contract.
    """
    body = json.dumps(
        {"Status": "SUCCESS", "Reason": "sim2real signal accounting", "UniqueId": unique_id, "Data": data}
    ).encode("utf-8")
    deadline = time.monotonic() + timeout_s
    last: object = None
    while time.monotonic() < deadline:
        req = _routed_request(ctx, handle_url, data=body, method="PUT", headers={"Content-Type": ""})
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                if 200 <= resp.status < 300:
                    return
                last = f"HTTP {resp.status}"
        except urllib.error.URLError as exc:
            last = exc
        time.sleep(2.0)
    raise AssertionError(
        f"could not PUT signal UniqueId={unique_id!r} to the wait condition handle within "
        f"{timeout_s}s (last={last!r})"
    )


def _status(cf, stack_name: str) -> str:
    stacks = cf.describe_stacks(StackName=stack_name)["Stacks"]
    assert stacks, f"DescribeStacks({stack_name!r}) returned no stacks; expected exactly 1"
    return stacks[0]["StackStatus"]


def _poll_status(cf, stack_name: str, predicate, *, timeout_s: float, why: str) -> str:
    """Poll DescribeStacks until predicate(status); RAISE on timeout, never return the last value."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = _status(cf, stack_name)
        if predicate(last):
            return last
        time.sleep(3.0)
    raise AssertionError(f"stack {stack_name!r} never satisfied [{why}] within {timeout_s}s (last={last!r})")


def _assert_frozen_in_progress(cf, stack_name: str, because: str) -> None:
    """Freeze detector: FREEZE_READS consecutive reads must all be CREATE_IN_PROGRESS.

    No timing assumption: the wait condition cannot be satisfiable, so no cadence explains a
    CREATE_COMPLETE here. The reads are spaced only to give the target room to be wrong.
    """
    seen = []
    for _ in range(FREEZE_READS):
        seen.append(_status(cf, stack_name))
        time.sleep(FREEZE_INTERVAL_S)
    assert set(seen) == {"CREATE_IN_PROGRESS"}, (
        f"stack {stack_name!r}: expected CREATE_IN_PROGRESS on all {FREEZE_READS} reads because "
        f"{because}, got {seen!r}"
    )


def _output(cf, stack_name: str, key: str) -> str:
    outputs = {o["OutputKey"]: o["OutputValue"] for o in cf.describe_stacks(StackName=stack_name)["Stacks"][0]["Outputs"]}
    assert key in outputs, f"stack {stack_name!r} Outputs: expected key {key!r}, got {sorted(outputs)!r}"
    return outputs[key]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
