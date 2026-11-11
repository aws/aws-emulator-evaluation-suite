"""modify-vpc-encryption-control-invalid-mode-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "modify-vpc-encryption-control-invalid-mode-rejected"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifyVpcEncryptionControl rejects a Mode value outside the {monitor, enforce}
    enum with a specific validation error, while a valid mode is applied successfully.
    """
    ec2 = ctx.client("ec2")

    vpc_id = ec2.create_vpc(
        CidrBlock="10.214.0.0/16",
        TagSpecifications=_tag_spec(ctx, "vpc", "venc-vpc"),
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))

    control = ec2.create_vpc_encryption_control(
        VpcId=vpc_id,
        TagSpecifications=_tag_spec(ctx, "vpc-encryption-control", "venc"),
    )["VpcEncryptionControl"]
    control_id = control["VpcEncryptionControlId"]
    ctx.on_cleanup(
        lambda: ec2.delete_vpc_encryption_control(VpcEncryptionControlId=control_id)
    )

    settled = _poll_until(
        lambda: _describe_control(ec2, control_id),
        lambda c: not _is_in_progress(c["State"]),
        timeout_s=120,
        interval_s=3,
    )
    initial_mode = settled["Mode"]

    # Negative: "block-everything" is not a valid VpcEncryptionControlMode value.
    code, code_msg = _client_error(
        lambda: ec2.modify_vpc_encryption_control(
            VpcEncryptionControlId=control_id, Mode="block-everything"
        )
    )
    assert code == "InvalidParameterValue", (
        f"expected ModifyVpcEncryptionControl with Mode='block-everything' to fail "
        f"with InvalidParameterValue, got {code!r}"
    )
    assert code_msg == "Mode must be one of: [enforce, monitor]", code_msg

    # Effect absence: the mode was not changed by the rejected call.
    unchanged = _describe_control(ec2, control_id)
    assert unchanged["Mode"] == initial_mode, (
        f"expected Mode to remain {initial_mode!r} after the rejected call, "
        f"got {unchanged['Mode']!r}"
    )

    # Positive control: a valid mode value is accepted and applied.
    ec2.modify_vpc_encryption_control(VpcEncryptionControlId=control_id, Mode="monitor")
    applied = _poll_until(
        lambda: _describe_control(ec2, control_id),
        lambda c: not _is_in_progress(c["State"]) and c["Mode"] == "monitor",
        timeout_s=180,
        interval_s=5,
    )
    assert applied["Mode"] == "monitor", (
        f"expected Mode to converge to 'monitor', got {applied['Mode']!r}"
    )


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _client_error(fn):
    """Call fn() and return its (code, message). An unexpected success raises, because an
    emulator accepting input real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _is_in_progress(state):
    # Real AWS's VpcEncryptionControl State enum is not consistently named: a
    # bare present-participle ("creating"/"modifying") can appear alongside the
    # "*-in-progress" suffixed variant depending on the transition. Treat both
    # as still-converging so the poll below never mistakes an in-progress state
    # for the terminal one just because it doesn't match a single literal.
    if state.endswith("-failed"):
        return False
    return state.endswith("-in-progress") or state.endswith("ing")


def _describe_control(ec2, control_id):
    return ec2.describe_vpc_encryption_controls(VpcEncryptionControlIds=[control_id])[
        "VpcEncryptionControls"
    ][0]


def _tag_spec(ctx, resource_type, prefix):
    return [{"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": ctx.unique_name(f"sim2real-{prefix}-")}]}]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
