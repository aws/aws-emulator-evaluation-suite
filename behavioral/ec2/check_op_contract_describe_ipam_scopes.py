"""op-contract-describe-ipam-scopes."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "op-contract-describe-ipam-scopes"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ec2-ipam")
def run(ctx) -> None:
    """DescribeIpamScopes returns exactly one default private and one default public scope for a new IPAM,
    a well-formed unknown scope ID fails with InvalidIpamScopeId.NotFound, and DryRun answers
    DryRunOperation (exact messages)."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-ipamscope-")

    ipam = ec2.create_ipam(
        Description=name,
        Tier="free",
        TagSpecifications=[{"ResourceType": "ipam", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Ipam"]
    ipam_id = ipam["IpamId"]
    ctx.on_cleanup(lambda: ec2.delete_ipam(IpamId=ipam_id, Cascade=True))

    scopes = _poll_until(
        lambda: ec2.describe_ipam_scopes(
            Filters=[{"Name": "ipam-id", "Values": [ipam_id]}]
        )["IpamScopes"],
        lambda rows: len(rows) >= 2 and all(r["State"] == "create-complete" for r in rows),
        timeout_s=60.0,
    )
    assert scopes is not None and len(scopes) == 2, f"expected 2 default scopes, got {scopes}"
    types = sorted(s["IpamScopeType"] for s in scopes)
    assert types == ["private", "public"], f"unexpected scope types: {types}"
    assert all(s["IsDefault"] is True for s in scopes)
    # IpamScope objects do not carry a bare IpamId field; the parent ipam is
    # instead embedded in the scope's ARN.
    assert all(ipam_id in s["IpamArn"] for s in scopes), f"unexpected scopes: {scopes}"

    # A well-formed but nonexistent scope id must be reported as a lookup failure, not
    # silently ignored, when explicitly requested by id.
    code, message = _error(
        lambda: ec2.describe_ipam_scopes(IpamScopeIds=["ipam-scope-0000000000000000"])
    )
    assert code == "InvalidIpamScopeId.NotFound", f"expected NotFound, got {code!r}"
    assert message == (
        "The IPAM scope (ipam-scope-0000000000000000) does not exist."
    ), f"unexpected InvalidIpamScopeId.NotFound message: {message!r}"

    # Error boundary: DryRun.
    dry_code, dry_message = _error(lambda: ec2.describe_ipam_scopes(DryRun=True))
    assert dry_code == "DryRunOperation", f"expected DryRunOperation, got {dry_code!r}"
    assert dry_message == (
        "Request would have succeeded, but DryRun flag is set."
    ), f"unexpected DryRunOperation message: {dry_message!r}"


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
    raise AssertionError(f"condition not met within {timeout_s}s (last saw {result!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
