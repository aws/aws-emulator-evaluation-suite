"""ipam-default-scope-deletion-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ipam-default-scope-deletion-rejected"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control", "resource:account-singleton:ec2-ipam")
def run(ctx) -> None:
    """DeleteIpamScope rejects the auto-created default private/public scopes: they can
    only be removed by deleting the whole IPAM."""
    ec2 = ctx.client("ec2")

    ipam = _create_ipam_with_capacity(
        ctx, ec2,
        Description=ctx.unique_name("sim2real-ipam-scopereject-"),
        OperatingRegions=[{"RegionName": ctx.region}],
    )
    ipam_id = ipam["IpamId"]
    ctx.on_cleanup(lambda: ec2.delete_ipam(IpamId=ipam_id, Cascade=True))

    ipam = _poll_until(
        lambda: ec2.describe_ipams(IpamIds=[ipam_id])["Ipams"][0],
        lambda i: i["State"] == "create-complete",
        timeout_s=60,
    )
    private_scope_id = ipam["PrivateDefaultScopeId"]
    public_scope_id = ipam["PublicDefaultScopeId"]
    assert private_scope_id and public_scope_id and private_scope_id != public_scope_id

    # positive control: DeleteIpamScope must actually work on this account/target for an
    # ordinary, non-default scope. Without this, the rejection asserted below is
    # indistinguishable from a target whose DeleteIpamScope is simply broken end to end.
    control_scope_id = ec2.create_ipam_scope(
        IpamId=ipam_id,
        Description=ctx.unique_name("sim2real-scope-control-"),
    )["IpamScope"]["IpamScopeId"]
    control_scope = _poll_until(
        lambda: ec2.describe_ipam_scopes(IpamScopeIds=[control_scope_id])["IpamScopes"][0],
        lambda s: s["State"] == "create-complete",
        timeout_s=60,
    )
    assert control_scope["IsDefault"] is False, "control scope must be a non-default scope"
    control_delete = ec2.delete_ipam_scope(IpamScopeId=control_scope_id)["IpamScope"]
    assert control_delete["State"] in ("delete-in-progress", "delete-complete")
    _poll_until(
        lambda: _describe_scopes_tolerant(ec2, control_scope_id),
        lambda scopes: (not scopes) or scopes[0]["State"] == "delete-complete",
        timeout_s=60,
    )

    for default_scope_id in (private_scope_id, public_scope_id):
        code, message = _error(lambda sid=default_scope_id: ec2.delete_ipam_scope(IpamScopeId=sid))
        assert code == "IncorrectState", (
            f"expected a default-scope-protection error for {default_scope_id}, got {code}"
        )
        assert message == (
            "The specified action is not valid. "
            f"The scope {default_scope_id} is a default scope."
        ), (
            f"unexpected default-scope-protection message for {default_scope_id}: {message!r}"
        )

    # both default scopes must still be present and healthy after the rejected attempts
    scopes = ec2.describe_ipam_scopes(IpamScopeIds=[private_scope_id, public_scope_id])["IpamScopes"]
    assert {s["IpamScopeId"] for s in scopes} == {private_scope_id, public_scope_id}
    assert all(s["State"] == "create-complete" and s["IsDefault"] for s in scopes)


def _create_ipam_with_capacity(ctx, ec2, **kwargs):
    """CreateIpam, retrying ONLY the per-Region quota refusal (IPAMs per Region is 1 by default)
    while another IPAM finishes deleting, every 2 s to a deadline capped by ctx.time_left()."""
    left = ctx.time_left()
    cap = 480.0 if left is None else min(480.0, left)
    deadline = time.monotonic() + cap
    while True:
        try:
            return ec2.create_ipam(**kwargs)["Ipam"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceLimitExceeded":
                raise
            if time.monotonic() > deadline:
                raise AssertionError(
                    f"no IPAM slot freed within {cap:.0f} s: "
                    f"{exc.response['Error'].get('Message')!r}"
                ) from exc
            time.sleep(2)


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
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a default-scope-protection error, but the call SUCCEEDED: {result!r}")


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
