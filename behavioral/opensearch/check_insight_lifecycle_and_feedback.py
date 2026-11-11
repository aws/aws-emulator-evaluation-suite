"""insight-lifecycle-and-feedback."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "insight-lifecycle-and-feedback"
GROUP = "state-machine"
SERVICES = ["opensearch"]

ACCOUNT_ENTITY_REFUSAL = (
    "ValidationException",
    "1 validation error detected: Value 'Account' at 'entity.type' failed to satisfy "
    "constraint: Member must satisfy enum value set: [DomainName]",
)


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Account-entity insights are listed and describable with stable Type/DisplayName; feedback
    on an Account entity is refused on entity type, and on a missing DomainName (when no insights
    exist) with ResourceNotFoundException."""
    aos = ctx.client("opensearch")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    entity = {"Type": "Account", "Value": account_id}

    try:
        list_resp = aos.list_insights(Entity=entity)
    except ClientError as e:
        if e.response["Error"]["Code"] == "DisabledOperationException":
            raise AssertionError("Insights feature not enabled in this account/region")
        raise
    insights = list_resp.get("Insights", [])
    assert isinstance(insights, list), f"expected Insights to be a list, got {insights!r}"

    if insights:
        target = insights[0]
        insight_id = target["InsightId"]

        details = aos.describe_insight_details(Entity=entity, InsightId=insight_id)
        assert "Fields" in details and isinstance(details["Fields"], list), (
            f"expected a well-formed Fields list, got {details!r}"
        )

        # InsightFeedback is scoped to DomainName entities, so an Account entity is refused.
        got = _error(
            lambda: aos.insight_feedback(Entity=entity, InsightId=insight_id, Thumbs="Up")
        )
        assert got == ACCOUNT_ENTITY_REFUSAL, (
            f"expected {ACCOUNT_ENTITY_REFUSAL!r} for feedback on an Account entity, got {got!r}"
        )

        relisted = aos.list_insights(Entity=entity).get("Insights", [])
        relisted_by_id = {i["InsightId"]: i for i in relisted}
        assert insight_id in relisted_by_id, "insight disappeared after a rejected feedback attempt"
        again = relisted_by_id[insight_id]
        assert again["Type"] == target["Type"], f"Type changed: {target['Type']!r} -> {again['Type']!r}"
        assert again["DisplayName"] == target["DisplayName"], (
            f"DisplayName changed: {target['DisplayName']!r} -> {again['DisplayName']!r}"
        )
    else:
        # AWS answers DescribeInsightDetails for an unknown well-formed InsightId with a normal
        # response (empty Fields), not ResourceNotFoundException.
        bogus_id = "00000000-0000-0000-0000-000000000000"
        details = aos.describe_insight_details(Entity=entity, InsightId=bogus_id)
        assert "Fields" in details and isinstance(details["Fields"], list), (
            f"expected a well-formed (possibly empty) Fields list, got {details!r}"
        )

        # Contrast: the Account entity fails entity.type validation, while a missing DomainName
        # passes it and is refused for not existing.
        got_account = _error(
            lambda: aos.insight_feedback(Entity=entity, InsightId=bogus_id, Thumbs="Up")
        )
        assert got_account == ACCOUNT_ENTITY_REFUSAL, (
            f"expected {ACCOUNT_ENTITY_REFUSAL!r} for feedback on an Account entity, "
            f"got {got_account!r}"
        )

        absent_domain = ctx.unique_name("sim2real-behav-nod-")[:28].rstrip("-")
        got_domain = _error(
            lambda: aos.insight_feedback(
                Entity={"Type": "DomainName", "Value": absent_domain},
                InsightId=bogus_id,
                Thumbs="Up",
            )
        )
        assert got_domain == ("ResourceNotFoundException", "Resource not found"), (
            f"expected ResourceNotFoundException 'Resource not found' for feedback against a "
            f"nonexistent domain, got {got_domain!r}"
        )


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"]["Message"]
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
