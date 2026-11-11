"""managed-insight-rules-put-list-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "managed-insight-rules-put-list-lifecycle"
GROUP = "overly-permissive"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListManagedInsightRules returns an empty list for a DynamoDB table ARN on three reads, and
    PutManagedInsightRules for it reports a TEMPLATE_NAME ResourceNotFoundException Failures entry with
    its exact description, adding no rule, while a malformed ARN is rejected with InvalidParameterValue."""
    cw = ctx.client("cloudwatch")
    ddb = ctx.client("dynamodb")

    # Positive control: the API distinguishes a structurally malformed ARN (rejected outright) from
    # a well-formed-but-ineligible one (accepted, empty list) -- so a clean empty answer below is not
    # explained by "everything sent to this endpoint fails or is denied".
    malformed = _error(lambda: cw.list_managed_insight_rules(ResourceARN="not-a-valid-arn-at-all"))
    assert malformed == ("InvalidParameterValue", "INVALID_RESOURCE_ARN: Invalid ARN."), (
        f"expected the InvalidParameterValue rejection for a structurally malformed ResourceARN, got {malformed!r}"
    )

    table_name = ctx.unique_name("sim2real-mir-table-")
    ddb.create_table(
        TableName=table_name,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _swallow(lambda: ddb.delete_table(TableName=table_name)))
    ddb.get_waiter("table_exists").wait(TableName=table_name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    table_arn = ddb.describe_table(TableName=table_name)["Table"]["TableArn"]

    def _list_rules():
        return cw.list_managed_insight_rules(ResourceARN=table_arn).get("ManagedRules", [])

    # Three independent reads spaced out rule out an async provisioning path that would eventually
    # surface a template.
    for _ in range(3):
        rules = _list_rules()
        assert rules == [], (
            f"expected no managed Contributor Insights rule templates for a DynamoDB table in this "
            f"account/region, got {rules!r}"
        )
        time.sleep(5)

    # The specific refusal: PutManagedInsightRules against this ARN is rejected via a per-rule
    # Failures entry naming the ARN -- never a silent accept of a template that was never offered.
    put_resp = cw.put_managed_insight_rules(
        ManagedRules=[{"ResourceARN": table_arn, "TemplateName": "DynamoDBContributorInsights"}]
    )
    failures = put_resp.get("Failures", [])
    assert failures, (
        f"expected PutManagedInsightRules to reject an untemplated DynamoDB table ARN via Failures, "
        f"got {put_resp}"
    )
    assert failures[0].get("ExceptionType") == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for an unrecognized template name, got {failures[0]!r}"
    )
    assert failures[0].get("FailureCode") == "TEMPLATE_NAME", (
        f"expected a TEMPLATE_NAME failure code, got {failures[0]!r}"
    )
    assert failures[0].get("FailureDescription") == "Could not find template with the specified templateName.", (
        f"expected the exact FailureDescription for an untemplated table ARN, got {failures[0]!r}"
    )

    # Effect-absent, at the destination: the generic DescribeInsightRules view never grew a rule for
    # this table, and ListManagedInsightRules still reports nothing enabled for it.
    described = cw.describe_insight_rules().get("InsightRules", [])
    assert not any(table_name in r.get("Name", "") for r in described), (
        f"a rule referencing {table_name!r} appeared in DescribeInsightRules despite Put reporting Failures"
    )
    assert _list_rules() == [], "ListManagedInsightRules is no longer empty after the rejected Put"


def _swallow(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ResourceNotFoundException",
            "TableNotFoundException",
        ):
            raise


def _error(fn):
    """Call fn(); return the botocore error (Code, Message). An unexpected SUCCESS raises."""
    try:
        fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError("expected the call to raise a ClientError, but it succeeded")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
