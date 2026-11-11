"""op-contract-describe-vpc-encryption-controls."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-describe-vpc-encryption-controls"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeVpcEncryptionControls reflects a real control's lifecycle and rejects DryRun."""
    ec2 = ctx.client("ec2")

    vpc_id = ec2.create_vpc(
        CidrBlock="10.128.0.0/16", TagSpecifications=[_tag_spec(ctx, "vpc", "devc-vpc")]
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))

    created = ec2.create_vpc_encryption_control(
        VpcId=vpc_id, TagSpecifications=[_tag_spec(ctx, "vpc-encryption-control", "devc")]
    )["VpcEncryptionControl"]
    control_id = created["VpcEncryptionControlId"]

    def _cleanup_control():
        _poll_until(
            lambda: _describe_control(ec2, control_id)["State"],
            lambda s: s not in ("creating", "deleting"),
            timeout_s=120,
        )
        try:
            ec2.delete_vpc_encryption_control(VpcEncryptionControlId=control_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidVpcEncryptionControlId.NotFound":
                raise
            return
        _poll_until(
            lambda: _control_state_or_gone(ec2, control_id),
            lambda s: s in ("deleted", "gone"),
            timeout_s=180,
        )

    ctx.on_cleanup(_cleanup_control)

    entry = _poll_until(
        lambda: _describe_control(ec2, control_id),
        lambda e: e["State"] != "creating" and not e["State"].endswith("-in-progress"),
        timeout_s=180,
    )
    assert entry["VpcId"] == vpc_id, f"expected VpcId {vpc_id!r}, got {entry['VpcId']!r}"
    assert entry["State"] == "available", f"unexpected settled State {entry['State']!r}"

    code, message = _error(lambda: ec2.describe_vpc_encryption_controls(DryRun=True))
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code}"
    assert message == _DRY_RUN_MESSAGE, f"unexpected DryRunOperation message {message!r}"

    # distinct error boundary: a syntactically valid but nonexistent control id is rejected,
    # not silently returned as an empty result set
    bogus_id = control_id[:-1] + ("0" if control_id[-1] != "0" else "1")
    code_notfound, message_notfound = _error(
        lambda: ec2.describe_vpc_encryption_controls(VpcEncryptionControlIds=[bogus_id])
    )
    assert code_notfound == "InvalidVpcEncryptionControlId.NotFound", (
        f"expected a NotFound error describing a nonexistent VpcEncryptionControlId, "
        f"got {code_notfound!r}"
    )
    expected = "One or more of the VpcEncryptionControlIds provided do not exist"
    assert message_notfound == expected, f"expected message {expected!r}, got {message_notfound!r}"


_DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


def _tag_spec(ctx, resource_type: str, prefix: str) -> dict:
    return {
        "ResourceType": resource_type,
        "Tags": [{"Key": "Name", "Value": ctx.unique_name(f"sim2real-{prefix}-")}],
    }


def _describe_control(ec2, control_id: str) -> dict:
    resp = ec2.describe_vpc_encryption_controls(VpcEncryptionControlIds=[control_id])
    items = resp["VpcEncryptionControls"]
    assert len(items) == 1, f"expected exactly one control entry, got {len(items)}"
    return items[0]


def _control_state_or_gone(ec2, control_id: str) -> str:
    from botocore.exceptions import ClientError

    try:
        return _describe_control(ec2, control_id)["State"]
    except ClientError as err:
        if err.response["Error"]["Code"] == "InvalidVpcEncryptionControlId.NotFound":
            return "gone"
        raise


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, call unexpectedly succeeded: {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last value={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
