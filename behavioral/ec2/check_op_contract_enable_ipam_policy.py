"""op-contract-enableIpamPolicy."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-enableIpamPolicy"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ec2-ipam")
def run(ctx) -> None:
    """EnableIpamPolicy enables a new policy and echoes its ID, DryRun answers DryRunOperation, and an
    unknown policy ID fails with InvalidIpamPolicyId.NotFound (exact messages)."""
    ec2 = ctx.client("ec2")
    policy_id = _create_ipam_policy(ctx, ec2)

    resp = ec2.enable_ipam_policy(IpamPolicyId=policy_id)
    assert resp["IpamPolicyId"] == policy_id, resp
    ctx.on_cleanup(lambda: _ignore(lambda: ec2.disable_ipam_policy(IpamPolicyId=policy_id)))

    dry_run_code, dry_run_message = _client_error(
        lambda: ec2.enable_ipam_policy(IpamPolicyId=policy_id, DryRun=True)
    )
    assert dry_run_code == "DryRunOperation", f"expected DryRunOperation, got {dry_run_code}"
    expected_dry = "Request would have succeeded, but DryRun flag is set."
    assert dry_run_message == expected_dry, f"expected message {expected_dry!r}, got {dry_run_message!r}"

    fake_policy_id = _zeroed_id(policy_id)
    real_code, real_message = _client_error(lambda: ec2.enable_ipam_policy(IpamPolicyId=fake_policy_id))
    assert real_code == "InvalidIpamPolicyId.NotFound", (
        f"expected InvalidIpamPolicyId.NotFound, got {real_code}"
    )
    expected_nf = f"The ipam-policy ID '{fake_policy_id}' does not exist"
    assert real_message == expected_nf, f"expected message {expected_nf!r}, got {real_message!r}"
    assert real_code != dry_run_code


# ===== helpers =====


def _create_ipam_policy(ctx, ec2) -> str:
    name = ctx.unique_name("sim2real-behav-ipam-")
    ipam = _create_ipam_with_retry(
        ctx,
        ec2,
        Description=name,
        OperatingRegions=[{"RegionName": ctx.region}],
        TagSpecifications=[{"ResourceType": "ipam", "Tags": [{"Key": "Name", "Value": name}]}],
    )
    ipam_id = ipam["IpamId"]
    ctx.on_cleanup(lambda: _ignore(lambda: ec2.delete_ipam(IpamId=ipam_id, Cascade=True)))

    policy = ec2.create_ipam_policy(
        IpamId=ipam_id,
        ClientToken=ctx.unique_name("sim2real-behav-policy-"),
        TagSpecifications=[
            {"ResourceType": "ipam-policy", "Tags": [{"Key": "Name", "Value": name}]}
        ],
    )["IpamPolicy"]
    policy_id = policy["IpamPolicyId"]
    ctx.on_cleanup(lambda: _ignore(lambda: ec2.delete_ipam_policy(IpamPolicyId=policy_id)))
    return policy_id


def _create_ipam_with_retry(ctx, ec2, **kwargs):
    """The per-account IPAM quota is shared with concurrently running checks, and deleting their
    IPAMs is unsafe: retry ResourceLimitExceeded every 2 s for up to 60 s while their teardowns free it."""
    import time
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 60.0
    left = ctx.time_left()
    if left is not None:
        deadline = min(deadline, time.monotonic() + left)
    while True:
        try:
            return ec2.create_ipam(**kwargs)["Ipam"]
        except ClientError as err:
            if err.response["Error"]["Code"] != "ResourceLimitExceeded":
                raise
            if time.monotonic() >= deadline:
                raise AssertionError(f"account IPAM quota still exhausted after retrying up to 60 s: {err}") from err
        time.sleep(2)


def _client_error(fn):
    """Call fn() and return the (code, message) of the ClientError it raises. A call that
    succeeds raises AssertionError: accepting a call real AWS refuses must not read as a code
    mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _ignore(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "InvalidIpamId.NotFound",
            "InvalidIpamPolicyId.NotFound",
        ):
            raise


def _zeroed_id(real_id: str) -> str:
    prefix, _, suffix = real_id.rpartition("-")
    return f"{prefix}-{'0' * len(suffix)}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
