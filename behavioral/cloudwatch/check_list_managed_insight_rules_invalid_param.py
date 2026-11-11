"""list-managed-insight-rules-invalid-param."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-managed-insight-rules-invalid-param"
GROUP = "error-semantics"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListManagedInsightRules with a malformed ResourceARN returns InvalidParameterValue.

    Positive control: a syntactically well-formed ARN (of a resource that need not exist) is
    accepted and returns a (possibly empty) ManagedRules list rather than erroring.
    """
    cw = ctx.client("cloudwatch")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    well_formed_arn = f"arn:aws:sns:{ctx.region}:{account_id}:{ctx.unique_name('sim2real-mir-')}"
    ok = cw.list_managed_insight_rules(ResourceARN=well_formed_arn)
    assert ok["ManagedRules"] == [], f"expected no managed rules for a freshly-named ARN, got {ok['ManagedRules']}"

    malformed = "not-an-arn-at-all"
    try:
        cw.list_managed_insight_rules(ResourceARN=malformed)
        raise AssertionError("expected InvalidParameterValue for a malformed ResourceARN")
    except ClientError as e:
        code = e.response["Error"]["Code"]
        assert code == "InvalidParameterValue", f"expected InvalidParameterValue, got {code}"
        message = e.response["Error"].get("Message")
        assert message == 'INVALID_RESOURCE_ARN: Invalid ARN.', f"unexpected message: {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
