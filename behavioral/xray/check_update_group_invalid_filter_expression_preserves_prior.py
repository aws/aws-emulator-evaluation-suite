"""update-group-invalid-filter-expression-preserves-prior."""
from __future__ import annotations

import random
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-group-invalid-filter-expression-preserves-prior"
GROUP = 'overly-permissive'
SERVICES = ['xray']


def _hex(n: int) -> str:
    return "".join(random.choice("0123456789abcdef") for _ in range(n))


def _poll_until(probe, predicate, timeout_s=60, interval_s=2, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _group_names(xr, max_pages=25):
    names = set()
    token = None
    for _ in range(max_pages):
        page = xr.get_groups(**({"NextToken": token} if token else {}))
        names.update(g["GroupName"] for g in page.get("Groups", []) if g.get("GroupName"))
        token = page.get("NextToken")
        if not token:
            break
    return names


def _delete_group_and_confirm(xr, group_name, timeout_s=60):
    xr.delete_group(GroupName=group_name)
    _poll_until(
        lambda: _group_names(xr),
        lambda names: group_name not in names,
        timeout_s=timeout_s,
        interval_s=2,
        description=f"group {group_name} absent from GetGroups after delete",
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A malformed FilterExpression is parsed and refused with InvalidRequestException: CreateGroup
    creates no group, UpdateGroup leaves the prior expression and ARN intact, and a well-formed
    update then applies."""
    xr = ctx.client("xray")
    prefix = "sim2real-behav-xray-g-"
    malformed = 'service("unclosed'
    original = 'service("sim2real-behav-xray-a")'
    replacement = 'service("sim2real-behav-xray-b")'
    malformed_message = "Error Location: line 1, position 9 : Invalid input symbol: '\"unclosed'"

    # 1. CreateGroup refuses a malformed expression and creates nothing.
    doomed = f"{prefix}{_hex(10)}"
    try:
        accepted = xr.create_group(GroupName=doomed, FilterExpression=malformed)
    except ClientError as exc:
        err = exc.response["Error"]
        assert err.get("Code") == "InvalidRequestException", (
            f"CreateGroup with a malformed FilterExpression must be refused as "
            f"InvalidRequestException, got {err.get('Code')!r}: {err.get('Message')!r}"
        )
        assert err.get("Message") == malformed_message, (
            f"expected message {malformed_message!r}, got {err.get('Message')!r}"
        )
        assert exc.response["ResponseMetadata"]["HTTPStatusCode"] == 400, exc.response
    else:
        ctx.on_cleanup(lambda: _delete_group_and_confirm(xr, doomed))
        raise AssertionError(
            f"CreateGroup accepted the malformed FilterExpression {malformed!r}: {accepted!r}"
        )
    assert doomed not in _group_names(xr), (
        f"group {doomed} must not exist after its CreateGroup was refused"
    )

    # 2. Valid setup.
    name = f"{prefix}{_hex(10)}"
    created = xr.create_group(
        GroupName=name,
        FilterExpression=original,
        Tags=[{"Key": "sim2real", "Value": name}],
    )["Group"]
    ctx.on_cleanup(lambda: _delete_group_and_confirm(xr, name))
    assert created["FilterExpression"] == original, created
    group_arn = created["GroupARN"]
    assert group_arn, created

    # 3. Break exactly one thing: update only the expression, to a malformed one.
    try:
        updated = xr.update_group(GroupName=name, FilterExpression=malformed)
    except ClientError as exc:
        err = exc.response["Error"]
        assert err.get("Code") == "InvalidRequestException", (
            f"UpdateGroup with a malformed FilterExpression must be refused as "
            f"InvalidRequestException, got {err.get('Code')!r}: {err.get('Message')!r}"
        )
        assert err.get("Message") == malformed_message, (
            f"expected message {malformed_message!r}, got {err.get('Message')!r}"
        )
        assert exc.response["ResponseMetadata"]["HTTPStatusCode"] == 400, exc.response
    else:
        raise AssertionError(
            f"UpdateGroup accepted the malformed FilterExpression {malformed!r}: {updated!r}"
        )

    # 4. Effect absent: the refused update did not partially apply.
    after = xr.get_group(GroupName=name)["Group"]
    assert after["FilterExpression"] == original, (
        f"refused UpdateGroup must leave the prior FilterExpression {original!r} intact, "
        f"got {after!r}"
    )
    assert after["GroupARN"] == group_arn, after

    # 5. Control: a well-formed update on the same group applies.
    ok = xr.update_group(GroupName=name, FilterExpression=replacement)["Group"]
    assert ok["FilterExpression"] == replacement, ok
    reread = xr.get_group(GroupName=name)["Group"]
    assert reread["FilterExpression"] == replacement, reread
    assert reread["GroupARN"] == group_arn, reread


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
