"""op-contract-describeIpamExternalResourceVerificationTokens."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describeIpamExternalResourceVerificationTokens"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ec2-ipam")
def run(ctx) -> None:
    """DescribeIpamExternalResourceVerificationTokens returns a new token with its ID, IPAM ID and a
    generated TokenValue, and DryRun answers DryRunOperation with its exact message."""
    ec2 = ctx.client("ec2")
    ipam_id = _create_ipam(ctx, ec2)

    token = ec2.create_ipam_external_resource_verification_token(IpamId=ipam_id)[
        "IpamExternalResourceVerificationToken"
    ]
    token_id = token["IpamExternalResourceVerificationTokenId"]
    ctx.on_cleanup(
        lambda: ec2.delete_ipam_external_resource_verification_token(
            IpamExternalResourceVerificationTokenId=token_id
        )
    )

    def probe():
        resp = ec2.describe_ipam_external_resource_verification_tokens(
            IpamExternalResourceVerificationTokenIds=[token_id]
        )
        return resp.get("IpamExternalResourceVerificationTokens", [])

    items = _poll_until(probe, lambda v: len(v) == 1, timeout_s=30.0, interval_s=2.0)
    described = items[0]
    assert described["IpamExternalResourceVerificationTokenId"] == token_id, (
        f"expected described token id {token_id!r}, got "
        f"{described['IpamExternalResourceVerificationTokenId']!r}"
    )
    assert described["IpamId"] == ipam_id, (
        f"expected described IpamId {ipam_id!r}, got {described['IpamId']!r}"
    )
    assert described["TokenValue"], "TokenValue should be a nonempty generated value"

    code, message = _error(
        lambda: ec2.describe_ipam_external_resource_verification_tokens(DryRun=True)
    )
    assert code == "DryRunOperation", f"unexpected error code: {code}"
    assert message == (
        "Request would have succeeded, but DryRun flag is set."
    ), f"unexpected DryRunOperation message: {message!r}"


def _create_ipam(ctx, ec2) -> str:
    name = ctx.unique_name("sim2real-behav-ipam-")
    ipam = ec2.create_ipam(
        Description=name,
        TagSpecifications=[{"ResourceType": "ipam", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Ipam"]
    ipam_id = ipam["IpamId"]
    ctx.on_cleanup(lambda: ec2.delete_ipam(IpamId=ipam_id, Cascade=True))
    return ipam_id


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _error(fn):
    """Call fn() and return the (code, message) of the error it raises. A call
    that SUCCEEDS raises AssertionError: real AWS refuses it, so acceptance must
    not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
