"""op-contract-create-placement-group."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-create-placement-group"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreatePlacementGroup creates an available cluster group; a duplicate GroupName is rejected
    without replacing it, and after deletion the name can be reused with a new GroupId."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-pg-")

    resp = ec2.create_placement_group(
        GroupName=name,
        Strategy="cluster",
        TagSpecifications=[{"ResourceType": "placement-group", "Tags": [{"Key": "Name", "Value": name}]}],
    )
    pg = resp["PlacementGroup"]
    ctx.on_cleanup(lambda: ec2.delete_placement_group(GroupName=name))

    assert pg["GroupName"] == name, f"expected group name {name!r}, got {pg['GroupName']!r}"
    assert pg["Strategy"] == "cluster", f"expected strategy 'cluster', got {pg['Strategy']!r}"
    assert pg["GroupId"].startswith("pg-"), f"expected GroupId to start with 'pg-', got {pg['GroupId']!r}"
    assert pg["State"] in ("pending", "available"), f"unexpected initial state {pg['State']!r}"

    final_state = _poll_until(
        lambda: ec2.describe_placement_groups(GroupNames=[name])["PlacementGroups"][0]["State"],
        lambda state: state == "available",
        timeout_s=30.0,
        interval_s=1.5,
    )
    assert final_state == "available", f"placement group never reached available, got {final_state!r}"

    code, message = _client_error(lambda: ec2.create_placement_group(GroupName=name, Strategy="cluster"))
    assert code == "InvalidPlacementGroup.Duplicate", f"expected duplicate-name rejection, got {code!r}"
    expected_message = f"The placement group '{name}' already exists."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    still = ec2.describe_placement_groups(GroupNames=[name])["PlacementGroups"]
    assert len(still) == 1, f"expected exactly 1 placement group named {name!r}, got {len(still)}"
    assert still[0]["GroupId"] == pg["GroupId"], (
        f"expected the original group {pg['GroupId']!r} to survive the rejected duplicate, "
        f"got {still[0]['GroupId']!r}"
    )

    ec2.delete_placement_group(GroupName=name)
    restored = ec2.create_placement_group(
        GroupName=name,
        Strategy="cluster",
        TagSpecifications=[{"ResourceType": "placement-group", "Tags": [{"Key": "Name", "Value": name}]}],
    )["PlacementGroup"]
    assert restored["GroupName"] == name, f"expected restored group named {name!r}, got {restored['GroupName']!r}"
    assert restored["GroupId"] != pg["GroupId"], (
        f"expected a new GroupId after delete+recreate, got the same id {restored['GroupId']!r}"
    )


def _client_error(fn):
    """Return the (code, message) of fn()'s ClientError; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
