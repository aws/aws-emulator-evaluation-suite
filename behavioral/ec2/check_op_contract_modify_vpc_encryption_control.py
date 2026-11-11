"""op-contract-modify-vpc-encryption-control."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "op-contract-modify-vpc-encryption-control"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifyVpcEncryptionControl: success flips the enforcement Mode and the
    resource transitions through its *-in-progress state to available; DryRun is
    rejected with DryRunOperation."""
    ec2 = ctx.client("ec2")

    # The account's VPC limit is shared across every check in this suite (several
    # of which each provision their own throwaway VPC), so it is routinely
    # exhausted transiently by sibling checks running concurrently that haven't
    # finished tearing down their own VPCs yet. Retry the create for a bounded
    # window rather than failing immediately.
    vpc_id = _create_vpc_with_retry(
        ec2, CidrBlock="10.202.0.0/16", TagSpecifications=_tag_spec(ctx, "vpc", "venc-vpc")
    )
    # Deleting a VPC Encryption Control's enforcement path can leave the VPC's
    # underlying managed ENIs settling for a short window even after the control
    # itself reports "deleted" — a bare delete_vpc right after can transiently
    # hit DependencyViolation. Retry the VPC delete through that window instead
    # of letting a single failed attempt silently leak the VPC (the runner
    # swallows cleanup exceptions).
    ctx.on_cleanup(lambda: _delete_vpc_with_retry(ec2, vpc_id))

    created = ec2.create_vpc_encryption_control(
        VpcId=vpc_id, TagSpecifications=_tag_spec(ctx, "vpc-encryption-control", "venc")
    )["VpcEncryptionControl"]
    control_id = created["VpcEncryptionControlId"]

    def _cleanup_control():
        from botocore.exceptions import ClientError

        try:
            ec2.delete_vpc_encryption_control(VpcEncryptionControlId=control_id)
            _poll_until(
                lambda: _describe_control(ec2, control_id),
                lambda c: c is None or c.get("State") in ("deleted", "delete-failed"),
                timeout_s=120,
                interval_s=5,
            )
        except ClientError as exc:
            # A fully deleted control stops resolving: that is the gone answer.
            if exc.response["Error"]["Code"] != "InvalidVpcEncryptionControlId.NotFound":
                raise

    ctx.on_cleanup(_cleanup_control)

    initial = _poll_until(
        lambda: _describe_control(ec2, control_id),
        lambda c: c is not None and not _is_in_progress(c.get("State")),
        timeout_s=60,
        interval_s=5,
    )
    assert initial is not None and initial["State"] == "available", initial

    # error boundary: DryRun must reject without mutating the mode.
    err, err_message = _client_error(lambda: ec2.modify_vpc_encryption_control(VpcEncryptionControlId=control_id, Mode="enforce", DryRun=True))
    assert err == "DryRunOperation", err
    expected_message = "Request would have succeeded, but DryRun flag is set."
    assert err_message == expected_message, f"expected message {expected_message!r}, got {err_message!r}"

    # effect absence: the rejected DryRun call did not touch the mode.
    unmutated = _describe_control(ec2, control_id)
    assert unmutated is not None and unmutated["Mode"] == initial["Mode"], (initial, unmutated)

    # success path: switch to enforce mode and observe the transition to available.
    # Real AWS can take considerably longer than 5 minutes to converge a VPC
    # Encryption Control mode change to "available" (it has to (re)provision the
    # encryption enforcement path for every ENI in the VPC).
    # The control can still read 'available' in the old mode right after the call, so wait for
    # the new mode (or a failed state) once it has settled.
    ec2.modify_vpc_encryption_control(VpcEncryptionControlId=control_id, Mode="enforce")
    updated = _poll_until(
        lambda: _describe_control(ec2, control_id),
        lambda c: c is not None and not _is_in_progress(c.get("State"))
        and (c.get("Mode") == "enforce" or c.get("State", "").endswith("-failed")),
        timeout_s=1400,
        interval_s=15,
    )
    assert updated is not None and updated["State"] == "available", updated
    assert updated["Mode"] == "enforce", updated


# ===== helpers =====
def _tag_spec(ctx, resource_type, prefix):
    return [{"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": ctx.unique_name(f"sim2real-{prefix}-")}]}]


def _create_vpc_with_retry(ec2, timeout_s=900.0, interval_s=20.0, **kwargs):
    # VpcLimitExceeded is retried for up to 900 s: other VPCs in the account may take minutes to be deleted.
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return ec2.create_vpc(**kwargs)["Vpc"]["VpcId"]
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "VpcLimitExceeded" and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _delete_vpc_with_retry(ec2, vpc_id, timeout_s=180.0, interval_s=10.0):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ec2.delete_vpc(VpcId=vpc_id)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "DependencyViolation" and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _client_error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected a ClientError, call succeeded with {result!r}")


def _poll_until(probe, predicate, timeout_s=90.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _is_in_progress(state):
    # Any *-in-progress or bare present-participle state (creating, modifying, deleting, ...) is still converging.
    if state is None:
        return True
    if state.endswith("-in-progress"):
        return True
    if state.endswith("-failed"):
        return False
    return state.endswith("ing")


def _describe_control(ec2, control_id):
    resp = ec2.describe_vpc_encryption_controls(VpcEncryptionControlIds=[control_id])
    items = resp.get("VpcEncryptionControls", [])
    return items[0] if items else None


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
