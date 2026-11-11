"""op-contract-describeSecondaryInterfaces."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describeSecondaryInterfaces"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeSecondaryInterfaces succeeds with no filters (secondary network cards are a
    specialized feature most accounts never provision, so an empty set is expected) and
    honors DryRun without performing the lookup."""
    ec2 = ctx.client("ec2")

    resp = ec2.describe_secondary_interfaces(MaxResults=10)
    key, interfaces = _sole_list_field(resp)
    assert isinstance(interfaces, list), f"{key} is not a list: {interfaces!r}"
    for item in interfaces:
        assert "SecondaryInterfaceId" in item or "secondaryInterfaceId" in item, (
            f"item missing SecondaryInterfaceId: {item!r}"
        )

    code, msg = _client_error(lambda: ec2.describe_secondary_interfaces(DryRun=True))
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
