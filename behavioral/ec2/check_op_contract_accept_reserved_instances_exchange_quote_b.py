"""op-contract-acceptReservedInstancesExchangeQuote-b."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-acceptReservedInstancesExchangeQuote-b"
GROUP = "error-semantics"
SERVICES = ["ec2"]
DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


@tags("axis:rejection", "cap:c1", "cap:c5", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AcceptReservedInstancesExchangeQuote with DryRun fails DryRunOperation, and with a
    well-formed unowned Reserved Instance id fails InvalidReservedInstanceId, each with its exact
    message and a RequestId.
    """
    ec2 = ctx.client("ec2")
    fake_ri_id = "b7c4a1e2-1f3d-4a9c-9e2f-abcdefabcdef"  # well-formed UUID, not owned
    fake_offering_id = "b3f2c9de-8a71-4e5f-9c2d-000000000001"  # well-formed UUID, never a real offering

    info = _client_error_info(
        lambda: ec2.accept_reserved_instances_exchange_quote(
            ReservedInstanceIds=[fake_ri_id],
            TargetConfigurations=[{"OfferingId": fake_offering_id}],
            DryRun=True,
        )
    )
    assert info["code"] == "DryRunOperation", f"expected DryRunOperation, got {info['code']!r}"
    assert info["message"] == DRY_RUN_MESSAGE, (
        f"expected message {DRY_RUN_MESSAGE!r}, got {info['message']!r}"
    )
    assert info["request_id"], "expected a RequestId in ResponseMetadata"

    info2 = _client_error_info(
        lambda: ec2.accept_reserved_instances_exchange_quote(
            ReservedInstanceIds=[fake_ri_id],
            TargetConfigurations=[{"OfferingId": fake_offering_id}],
        )
    )
    assert info2["code"] == "InvalidReservedInstanceId", (
        f"expected InvalidReservedInstanceId, got {info2['code']!r}"
    )
    expected2 = f" [{fake_ri_id}]"
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
