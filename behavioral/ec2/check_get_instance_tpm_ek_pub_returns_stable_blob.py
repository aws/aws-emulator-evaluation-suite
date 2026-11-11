"""get-instance-tpm-ek-pub-returns-stable-blob."""
from __future__ import annotations

from typing import Any, Callable

from behavioral_harness import tags

CHECK = "get-instance-tpm-ek-pub-returns-stable-blob"
GROUP = "data-plane"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetInstanceTpmEkPub fails InvalidInstanceID.Malformed with "The instance ID '<id>' is
    malformed" for a never-issued well-formed id, identically on a repeat and for another key type
    and format, and for a structurally invalid id.
    """
    ec2 = ctx.client("ec2")
    bogus_instance_id = "i-0123456789abcdef0"
    invalid_instance_id = "i-not-a-valid-id"

    first = _error(
        lambda: ec2.get_instance_tpm_ek_pub(InstanceId=bogus_instance_id, KeyType="rsa-2048", KeyFormat="der")
    )
    code, message = first
    assert code == "InvalidInstanceID.Malformed", first
    assert message == f"The instance ID '{bogus_instance_id}' is malformed", first

    second = _error(
        lambda: ec2.get_instance_tpm_ek_pub(InstanceId=bogus_instance_id, KeyType="rsa-2048", KeyFormat="der")
    )
    assert second == first, (
        f"repeated calls for the same instance should be rejected identically, got {first!r} then {second!r}"
    )

    third = _error(
        lambda: ec2.get_instance_tpm_ek_pub(InstanceId=bogus_instance_id, KeyType="ecc-sec-p384", KeyFormat="tpmt")
    )
    assert third == first, (
        f"the instance-id check must fail the same way regardless of requested key type/format, got {third!r}"
    )

    structurally_invalid = _error(
        lambda: ec2.get_instance_tpm_ek_pub(InstanceId=invalid_instance_id, KeyType="rsa-2048", KeyFormat="der")
    )
    code, message = structurally_invalid
    assert code == "InvalidInstanceID.Malformed", (
        "a structurally invalid id (wrong shape, not just a failed checksum) should be rejected "
        f"with the same code, got {structurally_invalid!r}"
    )
    assert message == f"The instance ID '{invalid_instance_id}' is malformed", structurally_invalid


def _error(fn: Callable[[], Any]) -> tuple[str, str]:
    """Call fn() and return the (code, message) of the ClientError it raises; a call
    that succeeds raises AssertionError."""
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
