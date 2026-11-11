"""op-contract-modify-ipam-scope."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-modify-ipam-scope"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ec2-ipam")
def run(ctx) -> None:
    """ModifyIpamScope updates the private default scope's description, echoed and read back; an
    unknown scope id fails with InvalidIpamScopeId.NotFound and its exact message."""
    ec2 = ctx.client("ec2")
    _ipam_id, private_scope_id, _public_scope_id = _create_ipam(ctx, ec2)

    # success path
    resp = ec2.modify_ipam_scope(IpamScopeId=private_scope_id, Description="updated-by-sim2real")
    scope = resp["IpamScope"]
    assert scope["Description"] == "updated-by-sim2real", (
        f"expected updated-by-sim2real, got {scope['Description']!r}"
    )
    assert scope["IpamScopeId"] == private_scope_id, (
        f"expected {private_scope_id}, got {scope['IpamScopeId']!r}"
    )

    described = ec2.describe_ipam_scopes(IpamScopeIds=[private_scope_id])["IpamScopes"][0]
    assert described["Description"] == "updated-by-sim2real", (
        f"expected updated-by-sim2real, got {described['Description']!r}"
    )

    # error boundary: unknown scope id
    code, message = _client_error(
        lambda: ec2.modify_ipam_scope(IpamScopeId="ipam-scope-00000000000000000", Description="x")
    )
    assert code == "InvalidIpamScopeId.NotFound", f"expected InvalidIpamScopeId.NotFound, got {code}"
    expected_message = "The IPAM scope (ipam-scope-00000000000000000) does not exist."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _client_error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last


def _create_ipam(ctx, ec2):
    ipam = ec2.create_ipam(
        Description=ctx.unique_name("sim2real-behav-ipam-"),
        OperatingRegions=[{"RegionName": ctx.region}],
    )["Ipam"]
    ipam_id = ipam["IpamId"]

    def _cleanup():
        try:
            ec2.delete_ipam(IpamId=ipam_id, Cascade=True)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidIpamId.NotFound":
                raise

    ctx.on_cleanup(_cleanup)

    ipam = _poll_until(
        lambda: ec2.describe_ipams(IpamIds=[ipam_id])["Ipams"][0],
        lambda i: i["State"] == "create-complete",
        timeout_s=90,
        interval_s=3,
    )
    assert ipam is not None and ipam["State"] == "create-complete", "IPAM never reached create-complete"
    return ipam_id, ipam["PrivateDefaultScopeId"], ipam["PublicDefaultScopeId"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
