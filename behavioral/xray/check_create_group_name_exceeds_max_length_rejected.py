"""create-group-name-exceeds-max-length-rejected."""
from __future__ import annotations

import random
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-group-name-exceeds-max-length-rejected"
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
    """CreateGroup refuses a 33-character GroupName (modelled max 32) while exactly 32 succeeds;
    the refused group does not exist and the 32-character group is unaffected."""
    xr = ctx.client("xray")
    prefix = "sim2real-behav-xray-g-"
    at_max = f"{prefix}{_hex(10)}"            # 22 + 10 = 32, the boundary-legal length
    over_max = f"{prefix}{_hex(11)}"          # 22 + 11 = 33, one over
    assert len(at_max) == 32 and len(over_max) == 33, (at_max, over_max)

    # Valid setup at the boundary.
    created = xr.create_group(GroupName=at_max, FilterExpression='service("sim2real-behav-xray")')
    ctx.on_cleanup(lambda: _delete_group_and_confirm(xr, at_max))
    group = created["Group"]
    assert group["GroupName"] == at_max, group
    assert group["GroupARN"], group
    assert group["FilterExpression"] == 'service("sim2real-behav-xray")', group

    # Break exactly one thing: the name is one character too long.
    try:
        accepted = xr.create_group(
            GroupName=over_max, FilterExpression='service("sim2real-behav-xray")'
        )
    except ClientError as exc:
        err = exc.response["Error"]
        code = err.get("Code")
        assert code == "ValidationException", (
            f"a 33-character GroupName (modelled max 32) must be refused as ValidationException, "
            f"got {code!r}: {err.get('Message')!r}"
        )
        assert err.get("Message") == (
            f"1 validation error detected: Value '{over_max}' at 'groupName' failed to satisfy "
            f"constraint: Member must have length less than or equal to 32"
        ), f"the rejection must name the groupName length constraint, got {err!r}"
        assert exc.response["ResponseMetadata"]["HTTPStatusCode"] == 400, exc.response
    else:
        ctx.on_cleanup(lambda: _delete_group_and_confirm(xr, over_max))
        raise AssertionError(
            f"CreateGroup accepted a 33-character GroupName (modelled max 32): {accepted!r}"
        )

    # Effect absent.
    names = _group_names(xr)
    assert over_max not in names, f"refused group {over_max} must not appear in GetGroups"

    # Control: the 32-character group is intact and individually readable.
    assert at_max in names, f"control group {at_max} vanished: {sorted(names)!r}"
    fetched = xr.get_group(GroupName=at_max)["Group"]
    assert fetched["GroupARN"] == group["GroupARN"], fetched


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
