"""opensearch-log-publishing-to-a-group-without-an-es-grant-is-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "opensearch-log-publishing-to-a-group-without-an-es-grant-is-rejected"
GROUP = "rejection"
SERVICES = ["logs", "opensearch"]

_ENGINE_VERSION = "OpenSearch_2.11"
_MIN_CLUSTER_CONFIG = {
    "InstanceType": "t3.small.search",
    "InstanceCount": 1,
    "DedicatedMasterEnabled": False,
    "ZoneAwarenessEnabled": False,
}
_MIN_EBS_OPTIONS = {"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10}
_THROTTLE_CODES = ("ThrottlingException", "TooManyRequestsException", "RequestLimitExceeded")


@tags(
    "axis:rejection",
    "cap:c7",
    "concern:e2e",
    "concern:eventing",
    "concern:negative-classes",
    "plane:control",
)
def run(ctx) -> None:
    """CreateDomain publishing logs to a group whose policy does not grant es.amazonaws.com is refused
    with ValidationException and its message and creates no domain; once the group's policy grants
    it, the identical request succeeds and DescribeDomain echoes the group.
    """
    logs = ctx.client("logs")
    osc = ctx.client("opensearch")
    account = ctx.client("sts").get_caller_identity()["Account"]

    domain_name = ctx.unique_name("sim2real-osgrnt-")  # 16 + 12 hex = 28
    domain_arn = f"arn:aws:es:{ctx.region}:{account}:domain/{domain_name}"
    group_name = ctx.unique_name("sim2real-behav-osgrant-")
    logs.create_log_group(logGroupName=group_name, tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group_name))
    listed = logs.describe_log_groups(logGroupNamePrefix=group_name)["logGroups"]
    assert [g["logGroupName"] for g in listed] == [group_name], (
        f"expected exactly the log group {group_name} under its own unique prefix, got {listed!r}"
    )
    raw_arn = listed[0]["arn"]
    group_arn = raw_arn[: -len(":*")] if raw_arn.endswith(":*") else raw_arn
    no_policy = logs.describe_resource_policies(resourceArn=group_arn, policyScope="RESOURCE")[
        "resourcePolicies"
    ]
    assert no_policy == [], (
        f"expected the fresh group {group_name} to carry no RESOURCE-scoped policy, got "
        f"{no_policy!r}"
    )

    request = {
        "DomainName": domain_name,
        "EngineVersion": _ENGINE_VERSION,
        "ClusterConfig": dict(_MIN_CLUSTER_CONFIG),
        "EBSOptions": dict(_MIN_EBS_OPTIONS),
        "AccessPolicies": _account_access_policy(ctx, domain_name),
        "TagList": [{"Key": "sim2real", "Value": CHECK}],
        "LogPublishingOptions": {
            "INDEX_SLOW_LOGS": {"CloudWatchLogsLogGroupArn": group_arn, "Enabled": True}
        },
    }
    # Registered BEFORE the first create: if the target wrongly ACCEPTS the ungranted request, the
    # domain exists and must not leak past the failing assertion below.
    ctx.on_cleanup(lambda: _delete_domain_quietly(osc, domain_name))

    # --- 1. Negative: the group exists, the grant does not.
    refused = _create_domain(osc, request)
    assert refused is not None, (
        f"expected CreateDomain publishing INDEX_SLOW_LOGS to {group_arn}, whose resource policy "
        f"grants es.amazonaws.com nothing, to be REJECTED, but it was accepted"
    )
    assert refused[0] == "ValidationException", (
        f"expected CreateDomain to an ungranted log group to fail with ValidationException, got "
        f"{refused[0]!r}: {refused[1]!r}"
    )
    want_refusal = (
        f"The Resource Access Policy specified for the CloudWatch Logs log group {group_name} does "
        "not grant sufficient permissions for Amazon OpenSearch Service to create a log stream. "
        "Please check the Resource Access Policy."
    )
    assert refused[1] == want_refusal, (
        f"expected the ungranted-group refusal message {want_refusal!r}, got {refused[1]!r}"
    )
    # Effect absent: no domain of that name exists.
    absent = _describe_error(osc, domain_name)
    assert absent == ("ResourceNotFoundException", f"Domain not found: {domain_name}"), (
        f"expected the refused CreateDomain to leave no domain {domain_name}, DescribeDomain said "
        f"{absent!r}"
    )

    # --- 2. Break nothing else; repair the one thing: grant es.amazonaws.com on this group only.
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowOpenSearchLogDelivery",
                "Effect": "Allow",
                "Principal": {"Service": ["es.amazonaws.com"]},
                "Action": ["logs:PutLogEvents", "logs:CreateLogStream"],
                "Resource": f"{group_arn}:*",
                "Condition": {
                    "StringEquals": {"aws:SourceAccount": account},
                    "ArnLike": {"aws:SourceArn": domain_arn},
                },
            }
        ],
    }
    logs.put_resource_policy(policyDocument=json.dumps(policy_doc), resourceArn=group_arn)
    ctx.on_cleanup(lambda: _delete_group_policy(logs, group_arn))

    # --- 3. Positive control: the IDENTICAL request is now accepted. A resource policy exposes no
    # observable for "has become effective", so the refusal above is retried a bounded number of
    # times on exactly that code -- the retry is what makes this correct, the sleep merely cheaper.
    accepted = None
    for attempt in range(6):
        accepted = _create_domain(osc, request)
        if accepted is None or accepted[0] != "ValidationException":
            break
        time.sleep(5.0 * (1 + attempt))
    assert accepted is None, (
        f"expected the same CreateDomain to be accepted once {group_name}'s resource policy grants "
        f"es.amazonaws.com, got {accepted!r}"
    )
    status = osc.describe_domain(DomainName=domain_name)["DomainStatus"]
    assert status.get("Created") is True, (
        f"expected DescribeDomain to report the accepted domain {domain_name} as Created, got "
        f"Created={status.get('Created')!r} Processing={status.get('Processing')!r}"
    )
    got = (status.get("LogPublishingOptions") or {}).get("INDEX_SLOW_LOGS")
    assert got == {"CloudWatchLogsLogGroupArn": group_arn, "Enabled": True}, (
        f"expected DescribeDomain to echo INDEX_SLOW_LOGS -> {group_arn} Enabled=True, got {got!r}"
    )


def _account_access_policy(ctx, domain_name: str) -> str:
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                    "Action": "es:*",
                    "Resource": f"arn:aws:es:{ctx.region}:{account_id}:domain/{domain_name}/*",
                }
            ],
        }
    )


def _delete_group_policy(logs, group_arn: str) -> None:
    """Teardown: a RESOURCE-scoped delete must name the policy's current revision."""
    for policy in logs.describe_resource_policies(resourceArn=group_arn, policyScope="RESOURCE")[
        "resourcePolicies"
    ]:
        logs.delete_resource_policy(resourceArn=group_arn, expectedRevisionId=policy["revisionId"])


def _delete_domain_quietly(osc, domain_name: str) -> None:
    """Idempotent teardown: only not-found is swallowed. DeleteDomain is asynchronous."""
    try:
        osc.delete_domain(DomainName=domain_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _create_domain(osc, request: dict):
    """CreateDomain(**request). Returns None when accepted, else (code, message). Throttling is
    retried with a bounded backoff; it is our rate, not the service's verdict on the request."""
    last_code = None
    for attempt in range(12):
        try:
            osc.create_domain(**request)
            return None
        except ClientError as exc:
            last_code = exc.response["Error"]["Code"]
            if last_code in _THROTTLE_CODES:
                time.sleep(6.0 * (1 + attempt))
                continue
            return last_code, exc.response["Error"].get("Message", "")
    raise AssertionError(f"CreateDomain still throttled after 12 attempts (last {last_code!r})")


def _describe_error(osc, domain_name: str) -> tuple[str, str]:
    """The (code, message) DescribeDomain raises. A SUCCESS is not a code: it raises, so an emulator
    that created the domain anyway cannot read as a naming difference."""
    try:
        status = osc.describe_domain(DomainName=domain_name)["DomainStatus"]
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(
        f"expected no domain {domain_name} after the refused create, but DescribeDomain returned "
        f"it: Created={status.get('Created')!r} Processing={status.get('Processing')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
