"""op-contract-describe-tags."""
from __future__ import annotations

import random

from behavioral_harness import tags

CHECK = "op-contract-describe-tags"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeTags: a tag created via CreateTags round-trips through a resource-id
    filter (success contract); an unrecognized filter name is the distinct error
    boundary."""
    ec2 = ctx.client("ec2")
    cidr = f"10.{random.randint(0, 200)}.0.0/16"
    vpc_id = ec2.create_vpc(CidrBlock=cidr)["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))

    tag_key = ctx.unique_name("sim2real-behav-key-")
    tag_value = "behavioral-check"
    ec2.create_tags(Resources=[vpc_id], Tags=[{"Key": tag_key, "Value": tag_value}])

    found = _poll_until(
        lambda: ec2.describe_tags(
            Filters=[
                {"Name": "resource-id", "Values": [vpc_id]},
                {"Name": "key", "Values": [tag_key]},
            ]
        )["Tags"],
        lambda tags_: len(tags_) == 1,
        timeout_s=30,
        interval_s=2,
    )
    assert found[0]["Key"] == tag_key, f"expected tag key {tag_key!r}, got {found[0]['Key']!r}"
    assert found[0]["Value"] == tag_value, (
        f"expected tag value {tag_value!r}, got {found[0]['Value']!r}"
    )
    assert found[0]["ResourceId"] == vpc_id, (
        f"expected ResourceId {vpc_id!r}, got {found[0]['ResourceId']!r}"
    )

    # Error boundary: unrecognized filter name.
    code, code_message = _error_code(
        lambda: ec2.describe_tags(Filters=[{"Name": "not-a-real-filter", "Values": ["x"]}])
    )
    assert code == "InvalidParameterValue", f"expected InvalidParameterValue, got {code!r}"
    expected_code_message = "The filter 'not-a-real-filter' is invalid"
    assert code_message == expected_code_message, f"expected message {expected_code_message!r}, got {code_message!r}"


def _error_code(fn):
    """Call fn() and return its (code, message); a call that succeeds raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=30.0, interval_s=1.0):
    import time

    deadline = time.monotonic() + timeout_s
    result = probe()
    while not predicate(result):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s (last={result!r})")
        time.sleep(interval_s)
        result = probe()
    return result


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
