"""op-contract-describeSecondaryNetworks."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describeSecondaryNetworks"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeSecondaryNetworks succeeds with no filters (an empty set is expected for
    accounts without RDMA secondary networks provisioned) and honors DryRun."""
    ec2 = ctx.client("ec2")

    resp = ec2.describe_secondary_networks(MaxResults=10)
    key, networks = _sole_list_field(resp)
    assert isinstance(networks, list), f"{key} is not a list: {networks!r}"
    for item in networks:
        assert "SecondaryNetworkId" in item or "secondaryNetworkId" in item, (
            f"item missing SecondaryNetworkId: {item!r}"
        )

    code, msg = _client_error(lambda: ec2.describe_secondary_networks(DryRun=True))
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code!r}"
    expected_msg = "Request would have succeeded, but DryRun flag is set."
    assert msg == expected_msg, f"expected message {expected_msg!r}, got {msg!r}"


def _client_error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _sole_list_field(resp):
    skip = {"ResponseMetadata", "NextToken", "RequestId"}
    for k, v in resp.items():
        if k in skip:
            continue
        if isinstance(v, list):
            return k, v
    raise AssertionError(f"no list field found in response: {sorted(resp.keys())}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
