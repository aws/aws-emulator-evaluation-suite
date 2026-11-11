"""op-contract-describe-ipams-superseded-stub."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "op-contract-describe-ipams-superseded-stub"
GROUP = "error-semantics"
SERVICES = ["ec2"]

_DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ec2-ipam")
def run(ctx) -> None:
    """DescribeIpams returns a new IPAM in create-complete with its Description and free tier, and DryRun
    answers DryRunOperation with its exact message."""
    ec2 = ctx.client("ec2")

    description = ctx.unique_name("sim2real-behav-ipams2-")
    created = ec2.create_ipam(
        Description=description,
        Tier="free",
        TagSpecifications=[{"ResourceType": "ipam", "Tags": [{"Key": "Name", "Value": description}]}],
    )["Ipam"]
    ipam_id = created["IpamId"]
    ctx.on_cleanup(lambda: ec2.delete_ipam(IpamId=ipam_id, Cascade=True))

    found = _poll_until(
        lambda: _find(ec2.describe_ipams(Filters=[{"Name": "ipam-id", "Values": [ipam_id]}])["Ipams"], ipam_id),
        lambda item: item is not None and item["State"] == "create-complete",
        timeout_s=60.0,
    )
    assert found["IpamId"] == ipam_id, f"expected {ipam_id}, got {found['IpamId']!r}"
    assert found["Description"] == description, f"expected {description!r}, got {found['Description']!r}"
    assert found["Tier"] == "free", f"expected 'free', got {found['Tier']!r}"
    assert found["State"] == "create-complete", f"expected 'create-complete', got {found['State']!r}"

    code, message = _client_error(lambda: ec2.describe_ipams(DryRun=True))
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code!r}"
    assert message == _DRY_RUN_MESSAGE, f"expected {_DRY_RUN_MESSAGE!r}, got {message!r}"


def _find(rows, ipam_id):
    for row in rows:
        if row.get("IpamId") == ipam_id:
            return row
    return None


def _client_error(fn):
    """Call fn() and return the (code, message) it is refused with; an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    result = None
    while time.monotonic() < deadline:
        result = probe()
        if predicate(result):
            return result
        time.sleep(interval_s)
    raise AssertionError(f"condition not observed within {timeout_s}s; last saw {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
