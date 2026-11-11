"""op-contract-acceptAddressTransfer."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-acceptAddressTransfer"
GROUP = "error-semantics"
SERVICES = ["ec2"]
DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AcceptAddressTransfer: DryRun proves the IAM-permission contract fires
    before any address-transfer business logic; a well-formed but unowned
    address is a distinct, well-known not-found error boundary."""
    ec2 = ctx.client("ec2")

    alloc = ec2.allocate_address(
        Domain="vpc",
        TagSpecifications=[
            {"ResourceType": "elastic-ip", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-eip-")}]}
        ],
    )
    allocation_id = alloc["AllocationId"]
    ctx.on_cleanup(lambda: ec2.release_address(AllocationId=allocation_id))
    public_ip = alloc["PublicIp"]

    # success-path contract: DryRun is an unconditional IAM-authorization
    # check that runs regardless of whether the address actually has a
    # pending transfer, so it must report DryRunOperation (not e.g. a
    # "no transfer" business error) when the caller has permission.
    info = _error_info(lambda: ec2.accept_address_transfer(Address=public_ip, DryRun=True))
    assert info["code"] == "DryRunOperation", f"expected DryRunOperation, got {info['code']!r}"
    assert info["message"] == DRY_RUN_MESSAGE, (
        f"expected message {DRY_RUN_MESSAGE!r}, got {info['message']!r}"
    )

    # distinct error boundary: a syntactically well-formed public IP that is
    # not an address the caller owns (or that exists at all in this
    # account) fails the same address-ownership lookup used for any other
    # elastic IP the caller doesn't own. (An out-of-range octet string like
    # "999.999.999.999" instead fails request syntax validation with a
    # different error, so a real-looking, unowned IP is used here.)
    unowned_ip = "203.0.113.123"
    info2 = _error_info(lambda: ec2.accept_address_transfer(Address=unowned_ip))
    assert info2["code"] == "InvalidAddress.NotFound", f"expected InvalidAddress.NotFound, got {info2['code']!r}"
    expected2 = f"The Elastic IP address '{unowned_ip}' does not exist or is not available."
    assert info2["message"] == expected2, (
        f"expected message {expected2!r}, got {info2['message']!r}"
    )


def _error_info(fn):
    """Call fn(); return its botocore error {code, message}. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return {"code": err["Code"], "message": err.get("Message")}
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
