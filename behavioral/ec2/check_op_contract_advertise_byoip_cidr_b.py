"""op-contract-advertiseByoipCidr-b."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-advertiseByoipCidr-b"
GROUP = "error-semantics"
SERVICES = ["ec2"]
DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AdvertiseByoipCidr with DryRun on a valid unprovisioned CIDR fails DryRunOperation, and on a
    malformed CIDR fails InvalidParameterValue, each with its exact message and a RequestId.
    """
    ec2 = ctx.client("ec2")

    info = _client_error_info(
        lambda: ec2.advertise_byoip_cidr(Cidr="198.51.100.0/24", DryRun=True)
    )
    assert info["code"] == "DryRunOperation", f"expected DryRunOperation, got {info['code']!r}"
    assert info["message"] == DRY_RUN_MESSAGE, (
        f"expected message {DRY_RUN_MESSAGE!r}, got {info['message']!r}"
    )
    assert info["request_id"], "expected a RequestId in ResponseMetadata"

    info2 = _client_error_info(
        lambda: ec2.advertise_byoip_cidr(Cidr="definitely-not-a-cidr")
    )
    assert info2["code"] == "InvalidParameterValue", (
        f"expected InvalidParameterValue, got {info2['code']!r}"
    )
    expected2 = "The CIDR (definitely-not-a-cidr) is not valid."
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
