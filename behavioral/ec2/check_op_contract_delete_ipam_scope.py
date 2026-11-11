"""op-contract-delete-ipam-scope."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-delete-ipam-scope"
GROUP = "error-semantics"
SERVICES = ["ec2"]

_DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ec2-ipam")
def run(ctx) -> None:
    """DeleteIpamScope with DryRun answers DryRunOperation and leaves a non-default empty scope; the real
    call deletes it, and ModifyIpamScope on its ID then fails with InvalidIpamScopeId.NotFound (exact
    messages)."""
    ec2 = ctx.client("ec2")

    ipam_name = ctx.unique_name("sim2real-ipam-")
    ipam = _create_ipam_with_capacity(
        ec2,
        Description=ipam_name,
        OperatingRegions=[{"RegionName": ctx.region}],
        TagSpecifications=[{"ResourceType": "ipam", "Tags": [{"Key": "Name", "Value": ipam_name}]}],
    )
    ipam_id = ipam["IpamId"]
    ctx.on_cleanup(lambda: ec2.delete_ipam(IpamId=ipam_id, Cascade=True))

    _poll_until(
        lambda: ec2.describe_ipams(IpamIds=[ipam_id])["Ipams"][0],
        lambda i: i["State"] == "create-complete",
        timeout_s=60,
    )

    scope_name = ctx.unique_name("sim2real-scope-")
    scope = ec2.create_ipam_scope(
        IpamId=ipam_id,
        Description=scope_name,
        TagSpecifications=[{"ResourceType": "ipam-scope", "Tags": [{"Key": "Name", "Value": scope_name}]}],
    )["IpamScope"]
    scope_id = scope["IpamScopeId"]

    scope = _poll_until(
        lambda: ec2.describe_ipam_scopes(IpamScopeIds=[scope_id])["IpamScopes"][0],
        lambda s: s["State"] == "create-complete",
        timeout_s=60,
    )
    assert scope["IsDefault"] is False, "test scope must be a non-default scope"

    # error boundary: DryRun short-circuits with DryRunOperation, scope survives
    code, message = _error(lambda: ec2.delete_ipam_scope(IpamScopeId=scope_id, DryRun=True))
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code}"
    assert message == _DRY_RUN_MESSAGE, f"unexpected DryRunOperation message {message!r}"
    still_there = ec2.describe_ipam_scopes(IpamScopeIds=[scope_id])["IpamScopes"][0]
    assert still_there["State"] == "create-complete", (
        f"DryRun must not delete the scope, but state is now {still_there['State']!r}"
    )

    # success path: an empty, non-default scope deletes cleanly
    resp = ec2.delete_ipam_scope(IpamScopeId=scope_id)
    assert resp["IpamScope"]["IpamScopeId"] == scope_id, (
        f"expected delete response to echo {scope_id!r}, got {resp['IpamScope']['IpamScopeId']!r}"
    )
    assert resp["IpamScope"]["State"] in ("delete-in-progress", "delete-complete"), (
        f"expected a delete-in-progress/delete-complete state, got {resp['IpamScope']['State']!r}"
    )

    _poll_until(
        lambda: _describe_scopes_tolerant(ec2, scope_id),
        lambda scopes: (not scopes) or scopes[0]["State"] == "delete-complete",
        timeout_s=60,
    )

    # the deleted id is not just absent from a read - it is unusable for a mutation too
    code, message = _error(lambda: ec2.modify_ipam_scope(IpamScopeId=scope_id, Description="post-delete"))
    assert code == "InvalidIpamScopeId.NotFound", f"unexpected code for a mutation on the deleted scope {code}"
    assert message == f"The IPAM scope ({scope_id}) does not exist.", f"unexpected message {message!r}"


def _reclaim_ipam_quota(ec2):
    # The per-Region IPAM quota can be 1, so an interrupted run's "sim2real-*" IPAM can
    # exhaust it; cascade-delete stale sim2real IPAMs before creating a new one.
    try:
        existing = ec2.describe_ipams()["Ipams"]
    except ClientError:
        return
    stale = [i for i in existing if (i.get("Description") or "").startswith("sim2real-")]
    if not stale:
        return
    for ipam in stale:
        try:
            ec2.delete_ipam(IpamId=ipam["IpamId"], Cascade=True)
        except ClientError:
            pass
    _poll_until(
        lambda: ec2.describe_ipams()["Ipams"],
        lambda ipams: not any(
            (i.get("Description") or "").startswith("sim2real-") for i in ipams
        ),
        timeout_s=120,
    )


def _create_ipam_with_capacity(ec2, **kwargs):
    try:
        return ec2.create_ipam(**kwargs)["Ipam"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceLimitExceeded":
            raise
        _reclaim_ipam_quota(ec2)
        return ec2.create_ipam(**kwargs)["Ipam"]


def _describe_scopes_tolerant(ec2, scope_id):
    # once the scope is truly gone, DescribeIpamScopes raises NotFound instead of
    # returning an empty list - treat that as "deleted" for polling purposes.
    try:
        return ec2.describe_ipam_scopes(IpamScopeIds=[scope_id])["IpamScopes"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "InvalidIpamScopeId.NotFound":
            return []
        raise


def _error(fn):
    """Call fn() and return the (code, message) of the ClientError it raises; a call that
    succeeds raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded with {result!r}")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
