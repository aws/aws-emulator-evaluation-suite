"""op-contract-createVpcEncryptionControl."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-createVpcEncryptionControl"
GROUP = "error-semantics"
SERVICES = ["ec2"]

_DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateVpcEncryptionControl: success creates a VPC-scoped control that an independent
    read confirms reaches a terminal state with the default Mode; DryRun short-circuits; a
    second create on the same VPC is rejected and leaves exactly one control behind."""
    ec2 = ctx.client("ec2")
    if not hasattr(ec2, "create_vpc_encryption_control"):
        raise AssertionError("installed botocore lacks create_vpc_encryption_control")

    vpc_id = _create_vpc(ec2, ctx, "10.210.0.0/16")
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))

    # Error boundary: DryRun must short-circuit with DryRunOperation before mutating anything.
    err = _client_error(lambda: ec2.create_vpc_encryption_control(VpcId=vpc_id, DryRun=True))
    assert err.get("Code") == "DryRunOperation", f"expected DryRunOperation, got {err!r}"
    assert err.get("Message") == _DRY_RUN_MESSAGE, f"unexpected DryRun message: {err!r}"

    resp = ec2.create_vpc_encryption_control(
        VpcId=vpc_id,
        TagSpecifications=[_tag_spec(ctx, "vpc-encryption-control", "vec")],
    )
    vec = resp["VpcEncryptionControl"]
    vec_id = vec["VpcEncryptionControlId"]
    assert vec["VpcId"] == vpc_id, f"create response VpcId {vec['VpcId']!r} != {vpc_id!r}"

    def _cleanup_vec() -> None:
        try:
            ec2.delete_vpc_encryption_control(VpcEncryptionControlId=vec_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidVpcEncryptionControlId.NotFound":
                raise

    ctx.on_cleanup(_cleanup_vec)

    # Independent read (DescribeVpcEncryptionControls, not the create response) confirming
    # the control reaches a real terminal state -- not "creating", and not any of the
    # delete-side states, which a just-created control can never legitimately be in.
    entry = _poll_until(
        lambda: _describe_by_id(ec2, vec_id),
        lambda e: e["State"] != "creating",
        timeout_s=90.0,
    )
    assert entry["VpcId"] == vpc_id, f"described VpcId {entry['VpcId']!r} != {vpc_id!r}"
    terminal_create_states = {
        "available",
        "enforce-in-progress",
        "monitor-in-progress",
        "enforce-failed",
        "monitor-failed",
    }
    assert entry["State"] in terminal_create_states, (
        f"expected a terminal create-side state, got {entry['State']!r}"
    )
    # Observed on real AWS: a control created with no Mode argument defaults to "monitor".
    assert entry["Mode"] == "monitor", f"expected default Mode 'monitor', got {entry.get('Mode')!r}"

    # A second create for the same VPC must be rejected (a VPC has at most one control config).
    err2 = _client_error(lambda: ec2.create_vpc_encryption_control(VpcId=vpc_id))
    assert err2.get("Code") == "InvalidParameterValue", (
        f"expected InvalidParameterValue rejecting a duplicate create, got {err2!r}"
    )
    assert err2.get("Message") == "Vpc Encryption Control resource already exists for this VPC.", (
        f"unexpected duplicate-create message: {err2!r}"
    )

    # Terminal independent read: the rejected duplicate must not have left a second control
    # behind. Queried by VpcIds -- a different call shape than the by-id lookup above, and the
    # only one of the three calls in this check that can see more than one control.
    by_vpc = ec2.describe_vpc_encryption_controls(VpcIds=[vpc_id])["VpcEncryptionControls"]
    assert len(by_vpc) == 1, f"expected exactly one control for {vpc_id}, got {len(by_vpc)}: {by_vpc!r}"
    assert by_vpc[0]["VpcEncryptionControlId"] == vec_id, (
        f"expected {vec_id!r} listed for {vpc_id}, got {by_vpc[0]['VpcEncryptionControlId']!r}"
    )


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    accepting input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _describe_by_id(ec2, vec_id):
    items = ec2.describe_vpc_encryption_controls(VpcEncryptionControlIds=[vec_id])[
        "VpcEncryptionControls"
    ]
    assert len(items) == 1, f"expected exactly one control entry for {vec_id}, got {len(items)}"
    return items[0]


def _tag_spec(ctx, resource_type, prefix):
    return {
        "ResourceType": resource_type,
        "Tags": [{"Key": "Name", "Value": ctx.unique_name(f"sim2real-{prefix}-")}],
    }


def _poll_until(probe, predicate, *, timeout_s, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


def _create_vpc(ec2, ctx, cidr_block):
    """Create a VPC, failing loudly if the account has no quota left.

    A quota exhaustion is an environment precondition, not something a check may fix by deleting
    resources it does not own, so `VpcLimitExceeded` propagates.
    """
    return ec2.create_vpc(
        CidrBlock=cidr_block, TagSpecifications=[_tag_spec(ctx, "vpc", "vec-vpc")]
    )["Vpc"]["VpcId"]

if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
