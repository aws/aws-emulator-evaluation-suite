"""op-contract-disable-ipam-policy."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-disable-ipam-policy"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:ec2-ipam")
def run(ctx) -> None:
    """DisableIpamPolicy with DryRun answers DryRunOperation and the enabled policy stays enabled; the
    real call returns true and GetEnabledIpamPolicy reports none enabled; a nonexistent policy ID
    fails with InvalidIpamPolicyId.NotFound (exact messages)."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-disableipampolicy-")

    ipam = ec2.create_ipam(Description=name)["Ipam"]
    ipam_id = ipam["IpamId"]
    ctx.on_cleanup(lambda: _ignore(lambda: ec2.delete_ipam(IpamId=ipam_id, Cascade=True)))

    policy = ec2.create_ipam_policy(
        IpamId=ipam_id,
        TagSpecifications=[{"ResourceType": "ipam-policy", "Tags": [{"Key": "Name", "Value": name}]}],
    )["IpamPolicy"]
    policy_id = policy["IpamPolicyId"]
    ctx.on_cleanup(lambda: _ignore(lambda: ec2.disable_ipam_policy(IpamPolicyId=policy_id)))
    ctx.on_cleanup(lambda: _ignore(lambda: ec2.delete_ipam_policy(IpamPolicyId=policy_id)))

    # Positive control: enable the freshly created policy. EnableIpamPolicy can spuriously
    # report InvalidIpamPolicyId.NotFound for a short window while the new policy propagates,
    # so retry only on that specific code.
    _enable_with_retry(ec2, policy_id)

    # GetEnabledIpamPolicy lags EnableIpamPolicy's success response by a few seconds (an
    # immediate read can still report IpamPolicyEnabled=False), so poll until it converges.
    enabled_state = _poll_until(
        lambda: ec2.get_enabled_ipam_policy(),
        lambda s: s.get("IpamPolicyEnabled") is True,
        timeout_s=60.0,
        interval_s=3.0,
    )
    assert enabled_state.get("IpamPolicyEnabled") is True, (
        f"expected the policy to be enabled, got {enabled_state}"
    )
    assert enabled_state.get("IpamPolicyId") == policy_id, (
        f"expected enabled policy {policy_id}, got {enabled_state.get('IpamPolicyId')!r}"
    )

    # DryRun on the real, enabled policy proves the permission-check contract without
    # disabling anything.
    code, message = _client_error(lambda: ec2.disable_ipam_policy(IpamPolicyId=policy_id, DryRun=True))
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code}"
    assert message == "Request would have succeeded, but DryRun flag is set.", (
        f"unexpected DryRunOperation message: {message!r}"
    )
    still_enabled = ec2.get_enabled_ipam_policy()
    assert still_enabled.get("IpamPolicyEnabled") is True, "DryRun must not disable the policy"

    resp = ec2.disable_ipam_policy(IpamPolicyId=policy_id)
    assert resp.get("Return") is True, f"expected Return=True, got {resp.get('Return')!r}"

    # Independent read at a different operation: the disable's effect must be visible through
    # GetEnabledIpamPolicy, and no dangling IpamPolicyId claiming otherwise. Same propagation
    # lag as the enable leg, so poll here too.
    disabled_state = _poll_until(
        lambda: ec2.get_enabled_ipam_policy(),
        lambda s: s.get("IpamPolicyEnabled") is False,
        timeout_s=60.0,
        interval_s=3.0,
    )
    assert disabled_state.get("IpamPolicyEnabled") is False, (
        f"expected no policy enabled after DisableIpamPolicy, got {disabled_state}"
    )
    assert not disabled_state.get("IpamPolicyId"), (
        f"expected no dangling IpamPolicyId after disable, got {disabled_state.get('IpamPolicyId')!r}"
    )

    # Error boundary: DryRun short-circuits with the permission-check error before the policy
    # ID is resolved, even for an ID that does not exist.
    bogus_policy_id = _zeroed_id(policy_id)
    code, message = _client_error(lambda: ec2.disable_ipam_policy(
        IpamPolicyId=bogus_policy_id, DryRun=True
    ))
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code}"
    assert message == "Request would have succeeded, but DryRun flag is set.", (
        f"unexpected DryRunOperation message: {message!r}"
    )

    code, message = _client_error(lambda: ec2.disable_ipam_policy(IpamPolicyId=bogus_policy_id))
    assert code == "InvalidIpamPolicyId.NotFound", (
        f"expected InvalidIpamPolicyId.NotFound, got {code}"
    )
    assert message == f"The ipam-policy ID '{bogus_policy_id}' does not exist", (
        f"unexpected InvalidIpamPolicyId.NotFound message: {message!r}"
    )


def _client_error(fn):
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises, because a
    target ACCEPTING a call real AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _ignore(fn):
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


def _poll_until(probe, predicate, *, timeout_s, interval_s):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _enable_with_retry(ec2, policy_id, *, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last_code = None
    while time.monotonic() < deadline:
        try:
            ec2.enable_ipam_policy(IpamPolicyId=policy_id)
            return
        except ClientError as exc:
            last_code = exc.response["Error"]["Code"]
            if last_code != "InvalidIpamPolicyId.NotFound":
                raise
            time.sleep(interval_s)
    raise AssertionError(
        f"EnableIpamPolicy never succeeded for a freshly created policy within {timeout_s}s "
        f"(last error: {last_code})"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
