"""op-contract-get-enabled-ipam-policy."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-get-enabled-ipam-policy"
GROUP = "error-semantics"
SERVICES = ["ec2"]

_DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetEnabledIpamPolicy returns a well-shaped policy status on success and
    honors DryRun as a distinct permission-check error boundary."""
    ec2 = ctx.client("ec2")

    resp = ec2.get_enabled_ipam_policy()
    assert "IpamPolicyEnabled" in resp, f"GetEnabledIpamPolicy response missing IpamPolicyEnabled: {resp}"
    assert isinstance(resp["IpamPolicyEnabled"], bool), (
        f"IpamPolicyEnabled should be bool, got {type(resp['IpamPolicyEnabled'])!r}: {resp['IpamPolicyEnabled']!r}"
    )
    if resp["IpamPolicyEnabled"]:
        assert "IpamPolicyId" in resp and resp["IpamPolicyId"], (
            f"IpamPolicyEnabled=True but IpamPolicyId is missing/empty: {resp}"
        )
        assert resp.get("ManagedBy") in ("account", "delegated-administrator-for-ipam"), (
            f"expected ManagedBy in the modelled enum, got {resp.get('ManagedBy')!r}"
        )
    else:
        # No policy enabled: there must be no dangling policy id claiming otherwise.
        assert not resp.get("IpamPolicyId"), (
            f"IpamPolicyEnabled=False but IpamPolicyId is set: {resp.get('IpamPolicyId')!r}"
        )

    code, message = _error(lambda: ec2.get_enabled_ipam_policy(DryRun=True))
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code!r}"
    assert message == _DRY_RUN_MESSAGE, f"expected DryRun message {_DRY_RUN_MESSAGE!r}, got {message!r}"


def _error(fn):
    """Call fn(); return its error as (code, message). An unexpected SUCCESS raises rather than
    returning a falsy sentinel."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
