"""list-managed-insight-rules-missing-required-param-rejected."""
from __future__ import annotations

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-managed-insight-rules-missing-required-param-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListManagedInsightRules sent without ResourceARN (client-side validation off, so the request
    reaches the service) is rejected with MissingParameter and its exact message, while a valid
    ResourceARN returns an empty ManagedRules list."""
    cw = ctx.client("cloudwatch")
    novalidate_cw = ctx.client("cloudwatch", config=Config(parameter_validation=False))

    # Positive control: a syntactically valid ResourceARN is accepted and answered normally.
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    resource_arn = f"arn:aws:dynamodb:{ctx.region}:{account_id}:table/{ctx.unique_name('sim2real-behav-')}"
    resp = cw.list_managed_insight_rules(ResourceARN=resource_arn)
    assert resp["ManagedRules"] == [], resp["ManagedRules"]

    error = _client_error(lambda: novalidate_cw.list_managed_insight_rules())
    assert error.get("Code") == "MissingParameter", (
        f"expected MissingParameter for ResourceARN dropped entirely from the wire, got {error!r}"
    )
    assert error.get("Message") == 'MISSING_RESOURCE_ARN: The ResourceARN parameter must be present.', (
        f"expected the message to name the missing ResourceARN member, got {error.get('Message')!r}"
    )


def _client_error(fn):
    """Call fn(); return its botocore Error dict. A SUCCESS raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected a rejection but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

