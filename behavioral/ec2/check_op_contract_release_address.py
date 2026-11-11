"""op-contract-release-address."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-release-address"
GROUP = "error-semantics"
SERVICES = ["ec2"]

_MANAGED_TAG_KEY = "sim2real-managed"
_MANAGED_TAG_VALUE = "true"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ReleaseAddress frees a real Elastic IP so DescribeAddresses does not find it; a second release of
    that AllocationId and a never-issued AllocationId both fail with InvalidAllocationID.NotFound and
    the exact message."""
    ec2 = ctx.client("ec2")

    alloc = ec2.allocate_address(
        Domain="vpc",
        TagSpecifications=[
            {"ResourceType": "elastic-ip", "Tags": [{"Key": _MANAGED_TAG_KEY, "Value": _MANAGED_TAG_VALUE}]}
        ],
    )
    allocation_id = alloc["AllocationId"]
    public_ip = alloc["PublicIp"]
    released = False

    def _cleanup():
        if not released:
            try:
                ec2.release_address(AllocationId=allocation_id)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "InvalidAllocationID.NotFound":
                    raise

    ctx.on_cleanup(_cleanup)

    before = ec2.describe_addresses(AllocationIds=[allocation_id])["Addresses"]
    assert len(before) == 1 and before[0]["PublicIp"] == public_ip, (
        f"expected freshly allocated address {public_ip!r} to describe as itself, got {before}"
    )

    # --- success path ---
    ec2.release_address(AllocationId=allocation_id)
    released = True

    code, message = _client_error(lambda: ec2.describe_addresses(AllocationIds=[allocation_id]))
    assert code == "InvalidAllocationID.NotFound", f"expected released address to disappear, got code={code}"
    expected_message = f"The allocation ID '{allocation_id}' does not exist"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # --- mutation on the dead id: releasing it again must fail, not succeed silently ---
    code, message = _client_error(lambda: ec2.release_address(AllocationId=allocation_id))
    assert code == "InvalidAllocationID.NotFound", f"expected double-release of dead id to fail, got code={code}"
    expected_message = f"The allocation ID '{allocation_id}' does not exist"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # --- error boundary: releasing a never-issued allocation is the same distinct NotFound ---
    code, message = _client_error(lambda: ec2.release_address(AllocationId="eipalloc-00000000000000000"))
    assert code == "InvalidAllocationID.NotFound", f"unexpected code: {code}"
    expected_message = "The allocation ID 'eipalloc-00000000000000000' does not exist"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _client_error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
