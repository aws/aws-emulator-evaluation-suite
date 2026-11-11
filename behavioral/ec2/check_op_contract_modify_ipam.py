"""op-contract-modify-ipam."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-modify-ipam"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ec2-ipam")
def run(ctx) -> None:
    """ModifyIpam sets Description and MeteredAccount resource-owner, echoed and read back; an unknown
    IPAM id fails with InvalidIpamId.NotFound and its exact message."""
    ec2 = ctx.client("ec2")
    ipam_id, _private_scope_id, _public_scope_id = _create_ipam(ctx, ec2)

    resp = ec2.modify_ipam(
        IpamId=ipam_id, Description="updated-by-sim2real", MeteredAccount="resource-owner"
    )
    ipam = resp["Ipam"]
    assert ipam["Description"] == "updated-by-sim2real", (
        f"expected Description 'updated-by-sim2real' in ModifyIpam response, got {ipam['Description']!r}"
    )
    assert ipam["MeteredAccount"] == "resource-owner", (
        f"expected MeteredAccount 'resource-owner' in ModifyIpam response, got {ipam['MeteredAccount']!r}"
    )

    described = ec2.describe_ipams(IpamIds=[ipam_id])["Ipams"][0]
    assert described["Description"] == "updated-by-sim2real", (
        f"expected Description 'updated-by-sim2real' from an independent DescribeIpams, got {described['Description']!r}"
    )
    assert described["MeteredAccount"] == "resource-owner", (
        f"expected MeteredAccount 'resource-owner' from an independent DescribeIpams, got {described['MeteredAccount']!r}"
    )

    code, message = _client_error(lambda: ec2.modify_ipam(IpamId="ipam-00000000000000000", Description="x"))
    assert code == "InvalidIpamId.NotFound", f"expected InvalidIpamId.NotFound, got {code}"
    expected_message = "The IPAM (ipam-00000000000000000) does not exist."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _client_error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not observed within {timeout_s}s; last saw {last!r}")


def _create_ipam(ctx, ec2):
    name = ctx.unique_name("sim2real-behav-ipam-")
    ipam = ec2.create_ipam(
        Description=name,
        OperatingRegions=[{"RegionName": ctx.region}],
        TagSpecifications=[
            {
                "ResourceType": "ipam",
                "Tags": [{"Key": "Name", "Value": name}],
            }
        ],
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
        description=f"ipam {ipam_id} reaching create-complete",
    )
    return ipam_id, ipam["PrivateDefaultScopeId"], ipam["PublicDefaultScopeId"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
