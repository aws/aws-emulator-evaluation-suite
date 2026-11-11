"""put-managed-insight-rules-invalid-definition-rejected."""
from __future__ import annotations

import time

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-managed-insight-rules-invalid-definition-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutManagedInsightRules reports an unknown TemplateName as a per-entry ResourceNotFound.

    No rule gets enabled; a malformed ResourceARN and an empty ManagedRules list are top-level
    InvalidParameterValue errors.
    """
    cw = ctx.client("cloudwatch")
    ddb = ctx.client("dynamodb")

    # Use a real, existing resource (so any per-entry failure is attributable to the bogus
    # TemplateName itself, not to the resource not existing - a fabricated ELB ARN pointing at
    # a load balancer that was never created surfaces ResourceNotFoundException instead, which
    # would test the wrong thing).
    table_name = ctx.unique_name("sim2real-mir-badtpl-")
    ddb.create_table(
        TableName=table_name,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(lambda: _best_effort(lambda: ddb.delete_table(TableName=table_name)))
    table_arn = _wait_for_table_active(ddb, table_name)

    # No managed-rule template exists for a DynamoDB table, so a real TemplateName cannot be the
    # positive control. Structural positive control instead: a malformed ResourceARN is rejected
    # server-side, deterministically, through a *different* mechanism (a top-level
    # ClientError) than the per-entry Failure the negative below exercises - so the two are
    # not the same canned response wearing different labels.
    malformed_error = _client_error(
        lambda: cw.list_managed_insight_rules(ResourceARN="not-a-valid-arn-at-all")
    )
    assert malformed_error.get("Code") == "InvalidParameterValue", (
        f"expected InvalidParameterValue for a structurally malformed ResourceARN, "
        f"got {malformed_error!r}"
    )
    assert malformed_error.get("Message") == "INVALID_RESOURCE_ARN: Invalid ARN.", (
        f"unexpected message for a malformed ResourceARN: {malformed_error.get('Message')!r}"
    )

    # A well-formed ARN for the real, eligible table resolves without error (a well-formed,
    # possibly-empty list) - the operation is not simply denying every ResourceARN it sees.
    eligible_resp = cw.list_managed_insight_rules(ResourceARN=table_arn)
    assert isinstance(eligible_resp.get("ManagedRules"), list), (
        f"expected a well-formed ManagedRules list for a genuinely eligible resource, "
        f"got {eligible_resp!r}"
    )

    # Syntactically valid TemplateName (passes client-side pattern validation) but it does not
    # correspond to any real managed-rule template -> the service must reject this specific
    # entry, not silently enable a bogus rule.
    bogus_template = "NotARealManagedRuleTemplateXYZ"

    resp = cw.put_managed_insight_rules(
        ManagedRules=[{"TemplateName": bogus_template, "ResourceARN": table_arn}]
    )
    failures = resp.get("Failures", [])
    assert len(failures) == 1, f"expected exactly one partial failure, got {failures!r}"
    failure = failures[0]
    # The service reports a bogus TemplateName as ResourceNotFoundException (the template
    # doesn't resolve to a known managed rule), not InvalidParameterValueException.
    assert failure.get("ExceptionType") == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException, got {failure.get('ExceptionType')!r}"
    )
    # FailureResource is an optional per-entry field. For a bogus-TemplateName failure, the
    # service was found to populate it with the offending TemplateName itself (identifying which
    # part of the entry could not be resolved), not the ResourceARN - so only assert on it when
    # the service actually returns it, and when it does, it must correctly identify the bogus
    # template that caused the failure.
    failure_resource = failure.get("FailureResource")
    if failure_resource is not None:
        assert failure_resource == bogus_template, (
            f"expected FailureResource to reference {bogus_template!r}, got {failure_resource!r}"
        )
    assert failure.get("FailureCode") == "TEMPLATE_NAME", (
        f"expected FailureCode TEMPLATE_NAME, got {failure.get('FailureCode')!r}"
    )
    assert failure.get("FailureDescription") == "Could not find template with the specified templateName.", (
        f"unexpected FailureDescription for an unresolvable TemplateName: {failure.get('FailureDescription')!r}"
    )

    # Effect must be absent: no managed rule was actually enabled for that resource.
    listed = cw.list_managed_insight_rules(ResourceARN=table_arn).get("ManagedRules", [])
    enabled = [
        r for r in listed
        if r.get("RuleState", {}).get("State") == "ENABLED"
    ]
    assert enabled == [], f"a managed rule was unexpectedly enabled despite the rejected entry: {enabled}"

    # A separate top-level failure mode: ManagedRules present but empty must be rejected too,
    # distinct from the per-entry failure above. ManagedRules carries no size constraint in
    # botocore's model (only `required`), so an empty list is NOT intercepted client-side as a
    # ParamValidationError -- it actually reaches CloudWatch. A parameter-validation-disabled
    # client removes any dependency on that botocore implementation detail persisting.
    novalidate_cw = ctx.client("cloudwatch", config=Config(parameter_validation=False))
    error = _client_error(lambda: novalidate_cw.put_managed_insight_rules(ManagedRules=[]))
    assert error.get("Code") == "InvalidParameterValue", (
        f"expected InvalidParameterValue for an empty ManagedRules list, got {error!r}"
    )
    assert error.get("Message") == "EMPTY_MANAGED_RULES: ManagedRules cannot be an empty array.", (
        f"unexpected message for an empty ManagedRules list: {error.get('Message')!r}"
    )


def _wait_for_table_active(ddb, table_name: str, timeout_s: float = 120.0) -> str:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        desc = ddb.describe_table(TableName=table_name)["Table"]
        if desc["TableStatus"] == "ACTIVE":
            return desc["TableArn"]
        time.sleep(2)
    raise AssertionError(f"table {table_name} never became ACTIVE within {timeout_s}s")


def _best_effort(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ResourceNotFoundException",
            "TableNotFoundException",
        ):
            raise


def _client_error(fn) -> dict:
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because a target
    accepting input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected a rejection but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
