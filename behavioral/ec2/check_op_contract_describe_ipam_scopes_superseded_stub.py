"""op-contract-describe-ipam-scopes-superseded-stub."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "op-contract-describe-ipam-scopes-superseded-stub"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ec2-ipam")
def run(ctx) -> None:
    """DescribeIpamScopes returns a new IPAM's default private and public scopes under their IDs, and
    DryRun answers DryRunOperation with its exact message."""
    ec2 = ctx.client("ec2")

    name = ctx.unique_name("sim2real-behav-ipamscope2-")
    ipam = ec2.create_ipam(
        Description=name,
        Tier="free",
        TagSpecifications=[{"ResourceType": "ipam", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Ipam"]
    ipam_id = ipam["IpamId"]
    ctx.on_cleanup(lambda: ec2.delete_ipam(IpamId=ipam_id, Cascade=True))
    private_scope_id = ipam["PrivateDefaultScopeId"]
    public_scope_id = ipam["PublicDefaultScopeId"]

    scopes = _poll_until(
        lambda: ec2.describe_ipam_scopes(
            Filters=[{"Name": "ipam-id", "Values": [ipam_id]}]
        )["IpamScopes"],
        lambda rows: len(rows) >= 2,
        timeout_s=60.0,
    )
    assert scopes is not None and len(scopes) == 2, f"expected 2 default scopes, got {scopes}"
    by_id = {s["IpamScopeId"]: s for s in scopes}
    assert private_scope_id in by_id, f"private scope {private_scope_id} missing from {scopes}"
    assert public_scope_id in by_id, f"public scope {public_scope_id} missing from {scopes}"
    assert by_id[private_scope_id]["IpamScopeType"] == "private", (
        f"expected private, got {by_id[private_scope_id]['IpamScopeType']!r}"
    )
    assert by_id[public_scope_id]["IpamScopeType"] == "public", (
        f"expected public, got {by_id[public_scope_id]['IpamScopeType']!r}"
    )
    assert all(s["IsDefault"] is True for s in scopes), f"expected both default, got {scopes}"

    code, message = _error(lambda: ec2.describe_ipam_scopes(DryRun=True))
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code!r}"
    assert message == (
        "Request would have succeeded, but DryRun flag is set."
    ), f"unexpected DryRunOperation message: {message!r}"


def _error(fn):
    """Call fn() and return the (code, message) of the error it raises. A call
    that SUCCEEDS raises AssertionError: real AWS refuses it, so acceptance must
    not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


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
