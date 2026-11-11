"""op-contract-move-byoip-cidr-to-ipam-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "op-contract-move-byoip-cidr-to-ipam-rejected"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:ec2-ipam")
def run(ctx) -> None:
    """MoveByoipCidrToIpam fails with InvalidIpamPoolId.NotFound for an unknown IpamPoolId before the CIDR
    is inspected, and with InvalidCidr.NotFound for a real pool and a CIDR the account never
    provisioned; both exact messages are asserted."""
    ec2 = ctx.client("ec2")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    # error boundary #1: the IpamPoolId does not exist at all.
    code, message, _ = _client_error(
        lambda: ec2.move_byoip_cidr_to_ipam(
            Cidr="999.999.999.0/24",
            IpamPoolId="ipam-pool-00000000000000000",
            IpamPoolOwner=account_id,
        )
    )
    assert code == "InvalidIpamPoolId.NotFound", f"expected InvalidIpamPoolId.NotFound, got {code}"
    assert message == "The ipam-pool ID 'ipam-pool-00000000000000000' does not exist", f"unexpected InvalidIpamPoolId.NotFound message: {message!r}"

    # error boundary #2: a real pool exists, so the call must fail on something other
    # than the pool id. Real accounts are commonly limited to a single IPAM, so prefer
    # reusing one that already exists rather than unconditionally creating a new one
    # (which would raise ResourceLimitExceeded once the quota is already used).
    existing_ipams = ec2.describe_ipams()["Ipams"]
    if existing_ipams:
        ipam_id = existing_ipams[0]["IpamId"]
    else:
        ipam = ec2.create_ipam(
            Description=ctx.unique_name("sim2real-behav-ipam-"),
            TagSpecifications=[
                {
                    "ResourceType": "ipam",
                    "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-ipam-")}],
                }
            ],
        )["Ipam"]
        ipam_id = ipam["IpamId"]
        ctx.on_cleanup(lambda: ec2.delete_ipam(IpamId=ipam_id, Cascade=True))

    scopes = ec2.describe_ipam_scopes(Filters=[{"Name": "ipam-id", "Values": [ipam_id]}])["IpamScopes"]
    private_scope = next(s for s in scopes if s["IpamScopeType"] == "private")

    pool = ec2.create_ipam_pool(
        IpamScopeId=private_scope["IpamScopeId"],
        AddressFamily="ipv4",
        TagSpecifications=[
            {
                "ResourceType": "ipam-pool",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-pool-")}],
            }
        ],
    )["IpamPool"]
    pool_id = pool["IpamPoolId"]
    ctx.on_cleanup(lambda: ec2.delete_ipam_pool(IpamPoolId=pool_id, Cascade=True))

    state = _poll_until(
        lambda: ec2.describe_ipam_pools(IpamPoolIds=[pool_id])["IpamPools"][0]["State"],
        lambda s: s == "create-complete",
        timeout_s=60,
        interval_s=2,
    )
    assert state == "create-complete", f"pool never became create-complete, last={state}"

    code2, message2, _ = _client_error(
        lambda: ec2.move_byoip_cidr_to_ipam(
            Cidr="198.51.100.0/24",
            IpamPoolId=pool_id,
            IpamPoolOwner=account_id,
        )
    )
    assert code2 == "InvalidCidr.NotFound", (
        f"expected InvalidCidr.NotFound (a real pool but no such BYOIP CIDR on this "
        f"account), got {code2}"
    )
    assert message2 == "The CIDR (198.51.100.0/24) does not exist.", f"unexpected InvalidCidr.NotFound message: {message2!r}"


def _client_error(fn):
    """Call fn() and return (code, message, http_status) of the ClientError it raises.
    An unexpected success raises AssertionError rather than returning a falsy value."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message"), exc.response["ResponseMetadata"]["HTTPStatusCode"]
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
