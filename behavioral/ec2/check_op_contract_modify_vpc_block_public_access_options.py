"""op-contract-modify-vpc-block-public-access-options."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "op-contract-modify-vpc-block-public-access-options"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:vpc-block-public-access")
def run(ctx) -> None:
    """ModifyVpcBlockPublicAccessOptions with DryRun fails with DryRunOperation and the standard message
    and leaves the mode unchanged; without DryRun DescribeVpcBlockPublicAccessOptions reports the new
    InternetGatewayBlockMode with State update-complete. The original mode is restored on cleanup."""
    ec2 = ctx.client("ec2")

    current = ec2.describe_vpc_block_public_access_options()["VpcBlockPublicAccessOptions"]
    if current.get("ManagedBy", "account") != "account":
        raise AssertionError("VPC BPA options are managed by a declarative policy in this account")
    original_mode = current["InternetGatewayBlockMode"]
    new_mode = "block-ingress" if original_mode != "block-ingress" else "off"

    def _restore():
        # A modify is refused while an update is in progress, so the restore waits for the
        # in-flight one to settle, then waits for its own to complete.
        _poll_until(
            lambda: ec2.describe_vpc_block_public_access_options()["VpcBlockPublicAccessOptions"],
            lambda opts: opts["State"] != "update-in-progress",
            timeout_s=240,
            interval_s=5,
        )
        ec2.modify_vpc_block_public_access_options(InternetGatewayBlockMode=original_mode)
        _poll_until(
            lambda: ec2.describe_vpc_block_public_access_options()["VpcBlockPublicAccessOptions"],
            lambda opts: opts["InternetGatewayBlockMode"] == original_mode and opts["State"] == "update-complete",
            timeout_s=300,
            interval_s=5,
        )

    ctx.on_cleanup(_restore)

    # error boundary: DryRun must reject without mutating the account setting.
    err, err_msg = _client_error(lambda: ec2.modify_vpc_block_public_access_options(InternetGatewayBlockMode=new_mode, DryRun=True))
    assert err == "DryRunOperation", err
    assert err_msg == "Request would have succeeded, but DryRun flag is set.", err_msg
    unchanged = ec2.describe_vpc_block_public_access_options()["VpcBlockPublicAccessOptions"]
    assert unchanged["InternetGatewayBlockMode"] == original_mode, (
        f"DryRun mutated the account setting: expected {original_mode!r}, got {unchanged['InternetGatewayBlockMode']!r}"
    )

    # success path: real mutation, then poll for the update-complete transition. The
    # window is generous (observed in-progress past 90s on real AWS) and is bounded by
    # ctx's own body timeout, not by an unconditional sleep.
    ec2.modify_vpc_block_public_access_options(InternetGatewayBlockMode=new_mode)
    updated = _poll_until(
        lambda: ec2.describe_vpc_block_public_access_options()["VpcBlockPublicAccessOptions"],
        lambda opts: opts["InternetGatewayBlockMode"] == new_mode and opts["State"] == "update-complete",
        timeout_s=240,
        interval_s=5,
    )
    assert updated["InternetGatewayBlockMode"] == new_mode, updated
    assert updated["State"] == "update-complete", updated


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


def _poll_until(probe, predicate, timeout_s=90.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out after {timeout_s}s waiting for condition; last observed: {last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
