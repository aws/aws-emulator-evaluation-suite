"""put-managed-insight-rules-missing-param-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-managed-insight-rules-missing-param-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutManagedInsightRules rejects ManagedRules=[] with a top-level InvalidParameterValue.

    A non-empty entry with an unknown TemplateName instead gets a per-entry Failure on a 200,
    showing the call is not refused wholesale; neither call enables a rule.
    """
    cw = ctx.client("cloudwatch")
    ddb = ctx.client("dynamodb")

    table_name = ctx.unique_name("sim2real-managedci-empty-")
    ddb.create_table(
        TableName=table_name,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table_name))
    table_arn = _wait_table_active(ddb, table_name)

    before = cw.list_managed_insight_rules(ResourceARN=table_arn)["ManagedRules"]
    assert all(r.get("RuleState") is None for r in before), (
        f"expected no managed rule enabled yet for a freshly created table, got {before}"
    )

    # Negative: ManagedRules=[] passes boto3's own "required key present" check, so
    # this exercises the service's server-side minimum-length constraint at the top level.
    error = _client_error(lambda: cw.put_managed_insight_rules(ManagedRules=[]))
    assert error.get("Code") == "InvalidParameterValue", (
        f"expected InvalidParameterValue for ManagedRules=[], got {error!r}"
    )
    assert error.get("Message") == "EMPTY_MANAGED_RULES: ManagedRules cannot be an empty array.", (
        f"unexpected message for ManagedRules=[]: {error.get('Message')!r}"
    )

    # Effect absent: the top-level-rejected call enabled nothing for this resource.
    after_empty = cw.list_managed_insight_rules(ResourceARN=table_arn)["ManagedRules"]
    assert all(r.get("RuleState") is None for r in after_empty), (
        f"the rejected empty ManagedRules call must not enable anything, got {after_empty}"
    )

    # DynamoDB tables have no managed-rule template, so an enabled rule cannot be the control.
    # Positive control: a non-empty ManagedRules list against this SAME real, eligible
    # resource reaches per-entry processing instead of a top-level rejection, even though the
    # TemplateName itself does not resolve to anything real. If PutManagedInsightRules simply
    # refused every call for this account, this would also come back as a top-level
    # ClientError, not a 200 with a per-entry Failures item.
    bogus_template = ctx.unique_name("sim2real-bogus-template-")
    resp = cw.put_managed_insight_rules(
        ManagedRules=[{"ResourceARN": table_arn, "TemplateName": bogus_template}]
    )
    failures = resp.get("Failures", [])
    assert len(failures) == 1, f"expected exactly one per-entry Failure, got {failures!r}"
    assert failures[0].get("ExceptionType") == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for an unresolvable TemplateName, got {failures[0]!r}"
    )
    assert failures[0].get("FailureCode") == "TEMPLATE_NAME", (
        f"expected FailureCode TEMPLATE_NAME, got {failures[0]!r}"
    )
    assert failures[0].get("FailureDescription") == "Could not find template with the specified templateName.", (
        f"unexpected FailureDescription for an unresolvable TemplateName: {failures[0]!r}"
    )

    # Terminal read, independent of both mutating calls, at the destination: neither the
    # top-level-rejected nor the per-entry-failed call enabled anything.
    after_bogus = cw.list_managed_insight_rules(ResourceARN=table_arn)["ManagedRules"]
    assert all(r.get("RuleState") is None for r in after_bogus), (
        f"neither rejected call may enable a managed rule, got {after_bogus}"
    )


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because a target
    ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _wait_table_active(ddb, table_name, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    while True:
        desc = ddb.describe_table(TableName=table_name)["Table"]
        if desc["TableStatus"] == "ACTIVE":
            return desc["TableArn"]
        if time.monotonic() >= deadline:
            raise AssertionError(f"table {table_name} did not become ACTIVE in {timeout_s}s")
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
