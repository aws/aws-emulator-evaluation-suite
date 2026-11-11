"""put-managed-insight-rules-invalid-resource-arn-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "put-managed-insight-rules-invalid-resource-arn-rejected"
GROUP = "state-machine"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutManagedInsightRules reports a bogus ResourceARN as a per-entry InvalidParameterException.

    The same unknown TemplateName against a real table ARN is the control: it fails as
    ResourceNotFoundException, so only the ARN differs between the two calls. Nothing is enabled.
    """
    cw = ctx.client("cloudwatch")
    ddb = ctx.client("dynamodb")
    table_name = ctx.unique_name("sim2real-managedci-arn-")
    ddb.create_table(
        TableName=table_name,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table_name))
    table_arn = _wait_for_table_active(ddb, table_name)

    bogus_template = ctx.unique_name("sim2real-no-such-template-")
    bogus_arn = f"arn:aws:cloudwatch:{ctx.region}:111122223333:not-a-real-resource/does-not-exist"

    # No managed-rule template exists for a DynamoDB table, so a working TemplateName cannot
    # isolate the ARN. Control: the bogus TemplateName against a REAL ARN fails on the template.
    control_resp = cw.put_managed_insight_rules(
        ManagedRules=[{"ResourceARN": table_arn, "TemplateName": bogus_template}]
    )
    control_failures = control_resp.get("Failures", [])
    assert control_failures == [
        {
            "FailureResource": bogus_template,
            "ExceptionType": "ResourceNotFoundException",
            "FailureCode": "TEMPLATE_NAME",
            "FailureDescription": "Could not find template with the specified templateName.",
        }
    ], f"expected the bogus TemplateName to be rejected as a template problem, got {control_resp}"

    resp = cw.put_managed_insight_rules(
        ManagedRules=[{"ResourceARN": bogus_arn, "TemplateName": bogus_template}]
    )
    failures = resp.get("Failures", [])
    assert failures == [
        {
            "FailureResource": bogus_template,
            "ExceptionType": "InvalidParameterException",
            "FailureCode": "TEMPLATE_NAME",
            "FailureDescription": "Invalid ResourceArn.",
        }
    ], (
        f"expected the bogus-ARN failure to report the ARN itself (the control above already "
        f"shows this same TemplateName failing on its own), got {resp}"
    )

    # effect absent: neither call enabled anything for the real, eligible resource
    after = cw.list_managed_insight_rules(ResourceARN=table_arn)["ManagedRules"]
    assert all(r.get("RuleState") is None for r in after), after


def _wait_for_table_active(ddb, table_name, timeout_s=120.0, interval_s=3.0):
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
