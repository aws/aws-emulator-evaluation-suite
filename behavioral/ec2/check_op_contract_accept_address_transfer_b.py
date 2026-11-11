"""op-contract-acceptAddressTransfer-b."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-acceptAddressTransfer-b"
GROUP = "error-semantics"
SERVICES = ["ec2"]
DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AcceptAddressTransfer with DryRun on an owned address fails DryRunOperation, and on a
    well-formed unowned address fails InvalidAddress.NotFound, each with its exact message and a
    RequestId.
    """
    ec2 = ctx.client("ec2")

    alloc = ec2.allocate_address(
        Domain="vpc",
        TagSpecifications=[{"ResourceType": "elastic-ip", "Tags": [{"Key": "sim2real", "Value": "1"}]}],
    )
    allocation_id = alloc["AllocationId"]
    ctx.on_cleanup(lambda: ec2.release_address(AllocationId=allocation_id))
    public_ip = alloc["PublicIp"]

    info = _client_error_info(
        lambda: ec2.accept_address_transfer(Address=public_ip, DryRun=True)
    )
    assert info["code"] == "DryRunOperation", f"expected DryRunOperation, got {info['code']!r}"
    assert info["message"] == DRY_RUN_MESSAGE, (
        f"expected message {DRY_RUN_MESSAGE!r}, got {info['message']!r}"
    )
    assert info["request_id"], "expected a RequestId in ResponseMetadata"

    info2 = _client_error_info(
        lambda: ec2.accept_address_transfer(Address="203.0.113.124")
    )
    assert info2["code"] == "InvalidAddress.NotFound", (
        f"expected InvalidAddress.NotFound, got {info2['code']!r}"
    )
    expected2 = "The Elastic IP address '203.0.113.124' does not exist or is not available."
    assert info2["message"] == expected2, (
        f"expected message {expected2!r}, got {info2['message']!r}"
    )
    assert info2["request_id"], "expected a RequestId in ResponseMetadata"


def _client_error_info(fn):
    """Call fn(); return its botocore error. An unexpected SUCCESS raises, so a target
    that accepts what AWS refuses is not read as an error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return {
            "code": err["Code"],
            "message": err.get("Message"),
            "request_id": exc.response.get("ResponseMetadata", {}).get("RequestId"),
        }
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
