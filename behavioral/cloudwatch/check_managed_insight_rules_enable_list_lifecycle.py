"""managed-insight-rules-enable-list-lifecycle."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "managed-insight-rules-enable-list-lifecycle"
GROUP = "state-machine"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """For a DynamoDB table ARN, ListManagedInsightRules returns no templates and
    PutManagedInsightRules reports a ResourceNotFoundException/TEMPLATE_NAME failure,
    leaving no rule enabled."""
    ddb = ctx.client("dynamodb")
    cw = ctx.client("cloudwatch")

    table_name = ctx.unique_name("sim2real-mir-table-")
    ddb.create_table(
        TableName=table_name,
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table_name))

    deadline = time.monotonic() + 60.0
    table_arn = None
    while time.monotonic() < deadline:
        desc = ddb.describe_table(TableName=table_name)["Table"]
        if desc["TableStatus"] == "ACTIVE":
            table_arn = desc["TableArn"]
            break
        time.sleep(2.0)
    if table_arn is None:
        raise AssertionError("table never became ACTIVE")

    # Rules out a broadly denied credential as the cause of the refusal below.
    control_resp = cw.list_metrics(Namespace="AWS/DynamoDB")
    assert control_resp["ResponseMetadata"]["HTTPStatusCode"] == 200, (
        f"expected ListMetrics to succeed as a positive control, got {control_resp['ResponseMetadata']}"
    )

    catalog = cw.list_managed_insight_rules(ResourceARN=table_arn).get("ManagedRules")
    assert catalog == [], (
        f"expected no managed Contributor Insights rule templates for a DynamoDB table, "
        f"got {catalog!r} -- AWS may have made DynamoDB tables an eligible resource type"
    )

    put_resp = cw.put_managed_insight_rules(
        ManagedRules=[{"TemplateName": "DynamoDB", "ResourceARN": table_arn}]
    )
    failures = put_resp.get("Failures", [])
    assert len(failures) == 1, f"expected exactly one failure enabling a template for an ineligible resource, got {failures!r}"
    failure = failures[0]
    assert failure.get("ExceptionType") == "ResourceNotFoundException", (
        f"expected ExceptionType ResourceNotFoundException, got {failure.get('ExceptionType')!r}: {failure!r}"
    )
    assert failure.get("FailureCode") == "TEMPLATE_NAME", (
        f"expected FailureCode TEMPLATE_NAME, got {failure.get('FailureCode')!r}: {failure!r}"
    )

    after = cw.list_managed_insight_rules(ResourceARN=table_arn).get("ManagedRules", [])
    assert after == [], f"expected the failed PutManagedInsightRules to leave no rule enabled, got {after!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
