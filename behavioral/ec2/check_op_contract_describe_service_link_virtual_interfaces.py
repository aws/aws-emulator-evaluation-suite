"""op-contract-describeServiceLinkVirtualInterfaces."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describeServiceLinkVirtualInterfaces"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeServiceLinkVirtualInterfaces succeeds with no filters (an account without
    Outposts has no service link virtual interfaces) and honors DryRun."""
    ec2 = ctx.client("ec2")

    resp = ec2.describe_service_link_virtual_interfaces(MaxResults=10)
    key, interfaces = _sole_list_field(resp)
    assert isinstance(interfaces, list), f"{key} is not a list: {interfaces!r}"
    for item in interfaces:
        assert "ServiceLinkVirtualInterfaceId" in item or "serviceLinkVirtualInterfaceId" in item, (
            f"item missing ServiceLinkVirtualInterfaceId: {item!r}"
        )

    code, code_message = _error_code(lambda: ec2.describe_service_link_virtual_interfaces(DryRun=True))
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code!r}"
    expected_code_message = "Request would have succeeded, but DryRun flag is set."
    assert code_message == expected_code_message, f"expected message {expected_code_message!r}, got {code_message!r}"


def _error_code(fn):
    """Call fn() and return its (code, message); a call that succeeds raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


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
