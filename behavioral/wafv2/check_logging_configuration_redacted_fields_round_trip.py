"""logging-configuration-redacted-fields-round-trip."""
from __future__ import annotations

import json

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "logging-configuration-redacted-fields-round-trip"
GROUP = "representation"
SERVICES = ["wafv2"]


def _canon(fields):
    return sorted((json.dumps(f, sort_keys=True) for f in fields))



@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RedactedFields and LoggingFilter written via PutLoggingConfiguration come back
    structurally identical from GetLoggingConfiguration (selectors, filter tree, default)."""
    wafv2 = ctx.client("wafv2")
    logs = ctx.client("logs")
    scope = "REGIONAL"

    name = ctx.unique_name("sim2real-logcfg-")
    vis = {"SampledRequestsEnabled": False, "CloudWatchMetricsEnabled": False, "MetricName": name}
    created = wafv2.create_web_acl(
        Name=name, Scope=scope, DefaultAction={"Allow": {}}, VisibilityConfig=vis,
        Tags=[{"Key": "Team", "Value": "sim2real"}],
    )
    summary = created["Summary"]
    acl_id = summary["Id"]
    acl_arn = summary["ARN"]

    def _cleanup_acl():
        try:
            cur = wafv2.get_web_acl(Name=name, Scope=scope, Id=acl_id)
            wafv2.delete_web_acl(Name=name, Scope=scope, Id=acl_id, LockToken=cur["LockToken"])
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "WAFNonexistentItemException":
                raise

    ctx.on_cleanup(_cleanup_acl)

    log_group_name = ctx.unique_name("aws-waf-logs-sim2real-")
    logs.create_log_group(logGroupName=log_group_name, tags={"Team": "sim2real"})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group_name))

    log_group_arn = logs.describe_log_groups(logGroupNamePrefix=log_group_name)["logGroups"][0][
        "arn"
    ].rstrip(":*")

    redacted_fields = [
        {"SingleHeader": {"Name": "authorization"}},
        {"Method": {}},
        {"QueryString": {}},
    ]
    logging_filter = {
        "Filters": [
            {
                "Behavior": "DROP",
                "Requirement": "MEETS_ALL",
                "Conditions": [{"ActionCondition": {"Action": "COUNT"}}],
            }
        ],
        "DefaultBehavior": "KEEP",
    }

    wafv2.put_logging_configuration(
        LoggingConfiguration={
            "ResourceArn": acl_arn,
            "LogDestinationConfigs": [log_group_arn],
            "RedactedFields": redacted_fields,
            "LoggingFilter": logging_filter,
        }
    )
    ctx.on_cleanup(lambda: wafv2.delete_logging_configuration(ResourceArn=acl_arn))

    got = wafv2.get_logging_configuration(ResourceArn=acl_arn)["LoggingConfiguration"]
    assert got["ResourceArn"] == acl_arn, (
        f"ResourceArn changed on round trip: expected {acl_arn!r}, got {got['ResourceArn']!r}"
    )
    assert got["LogDestinationConfigs"] == [log_group_arn], (
        f"LogDestinationConfigs changed on round trip: expected [{log_group_arn!r}], "
        f"got {got['LogDestinationConfigs']!r}"
    )
    # AWS reorders RedactedFields, so compare as an order-independent multiset.
    assert _canon(got["RedactedFields"]) == _canon(redacted_fields), (
        f"RedactedFields structure changed on round trip: {got['RedactedFields']}"
    )
    assert got["LoggingFilter"] == logging_filter, (
        f"LoggingFilter structure changed on round trip: {got['LoggingFilter']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
