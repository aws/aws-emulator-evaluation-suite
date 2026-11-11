"""list-finding-aggregations-type-mismatch-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-finding-aggregations-type-mismatch-rejected"
GROUP = "overly-permissive"
SERVICES = ["inspector2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An aggregationType value that isn't a recognized enum member is rejected outright."""
    inspector2 = ctx.client("inspector2")

    # Positive control: aggregationType and aggregationRequest agree (ACCOUNT/accountAggregation).
    # The response does not echo aggregationType back (confirmed against real AWS, which returns
    # only {"responses": [...]} even though the Smithy model marks aggregationType as required
    # output) so the control asserts the well-formed shape instead of a field that is never there.
    ok = inspector2.list_finding_aggregations(
        aggregationType="ACCOUNT", aggregationRequest={"accountAggregation": {}}
    )
    assert isinstance(ok.get("responses"), list), f"expected a responses list, got {ok!r}"

    # Negative: aggregationType is not a member of the FindingAggregationType enum at all.
    code, msg = _error_code(
        lambda: inspector2.list_finding_aggregations(
            aggregationType="NOT_A_REAL_AGGREGATION_TYPE",
            aggregationRequest={"accountAggregation": {}},
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    assert msg == (
        "1 validation error detected: Value at 'aggregationType' failed to satisfy constraint: Member "
        "must satisfy enum value set: [AWS_EC2_INSTANCE, PACKAGE, REPOSITORY, ACCOUNT, IMAGE_LAYER, "
        "AWS_LAMBDA_FUNCTION, FINDING_TYPE, AWS_ECR_CONTAINER, TITLE, LAMBDA_LAYER, SERVERLESS_FUNCTION, "
        "CONTAINER_IMAGE, VM_INSTANCE, AMI]"
    ), msg


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(
        f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
