"""resource-policy-revision-conflict-rejected."""
from __future__ import annotations

import copy
import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "resource-policy-revision-conflict-rejected"
GROUP = "error-semantics"
SERVICES = ["logs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutResourcePolicy on a log-group-scoped policy enforces optimistic concurrency via
    expectedRevisionId: a malformed or superseded revision is rejected and leaves the policy as is.
    """
    logs = ctx.client("logs")
    group_name = ctx.unique_name("sim2real-behav-lg-")
    logs.create_log_group(logGroupName=group_name, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group_name))
    # describe_log_groups() appends a trailing ":*" wildcard suffix to the ARN
    # for backward-compatibility reasons; resource-based-tagging-style APIs
    # such as PutResourcePolicy/TagResource reject that suffixed form with
    # ValidationException("Invalid resourceArn"), so it must be stripped.
    raw_arn = logs.describe_log_groups(logGroupNamePrefix=group_name)["logGroups"][0]["arn"]
    log_group_arn = raw_arn[: -len(":*")] if raw_arn.endswith(":*") else raw_arn

    policy_doc_v1 = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "Route53LogsToCloudWatchLogs",
                "Effect": "Allow",
                "Principal": {"Service": ["route53.amazonaws.com"]},
                "Action": "logs:PutLogEvents",
                "Resource": log_group_arn,
            }
        ],
    }
    # For the log-group-scoped resource policy, resourceArn identifies the
    # policy; real CloudWatch Logs rejects the call with
    # InvalidParameterException("Both policy name and resource arn cannot be
    # specified") if policyName is also supplied, so only resourceArn is used
    # here (policyName is reserved for the separate account-scoped policy API).
    logs.put_resource_policy(
        policyDocument=json.dumps(policy_doc_v1),
        resourceArn=log_group_arn,
    )
    ctx.on_cleanup(lambda: _delete_resource_policy(logs, log_group_arn))
    # Real CloudWatch Logs does not echo the revisionId in the PutResourcePolicy
    # response itself; it must be looked up via DescribeResourcePolicies. Passing
    # resourceArn implies a resource-scoped policy, so policyScope="RESOURCE"
    # must be supplied explicitly -- the default scope is ACCOUNT, and real
    # CloudWatch Logs rejects resourceArn with InvalidParameterException
    # ("Cannot provide ResourceArn for PolicyScope") unless RESOURCE is set.
    described_initial = logs.describe_resource_policies(
        resourceArn=log_group_arn, policyScope="RESOURCE"
    )["resourcePolicies"]
    assert len(described_initial) == 1, f"expected exactly one resource policy, got {described_initial}"
    real_revision_id = described_initial[0]["revisionId"]
    assert real_revision_id, "expected DescribeResourcePolicies to report a non-empty revisionId"
    # Real CloudWatch Logs may normalize the stored policy document (e.g.
    # re-serializing/re-ordering fields) relative to exactly what was
    # submitted, so the canonical "current document" baseline for the
    # unchanged-after-rejection check must come from what the service
    # actually echoes back here, not from the locally-constructed dict.
    canonical_doc_v1 = json.loads(described_initial[0]["policyDocument"])

    # error boundary: updating with a stale/wrong expectedRevisionId is rejected
    # NOTE: a shallow dict() copy shares the nested "Statement" list/dict with
    # canonical_doc_v1, so mutating it below would corrupt the original for the
    # later equality check -- deepcopy to keep the two documents independent.
    policy_doc_v2 = copy.deepcopy(canonical_doc_v1)
    policy_doc_v2["Statement"][0]["Sid"] = "UpdatedSid"
    stale_revision_id = real_revision_id + "-stale"
    code, msg = _error(
        lambda: logs.put_resource_policy(
            policyDocument=json.dumps(policy_doc_v2),
            resourceArn=log_group_arn,
            expectedRevisionId=stale_revision_id,
        )
    )
    assert code == "InvalidParameterException", f"got {code!r}"
    assert msg == "Invalid ExpectedRevisionId", f"got {msg!r}"

    # the policy document must be unchanged after the rejected update
    described = logs.describe_resource_policies(
        resourceArn=log_group_arn, policyScope="RESOURCE"
    )["resourcePolicies"]
    assert len(described) == 1, f"expected exactly one resource policy, got {described}"
    stored_after_rejection = json.loads(described[0]["policyDocument"])
    assert stored_after_rejection == canonical_doc_v1, (
        f"expected policy document unchanged after rejected update, "
        f"expected {canonical_doc_v1}, got {stored_after_rejection}"
    )

    # sanity: the correct current revisionId is still accepted
    logs.put_resource_policy(
        policyDocument=json.dumps(policy_doc_v2),
        resourceArn=log_group_arn,
        expectedRevisionId=real_revision_id,
    )
    described_after = logs.describe_resource_policies(
        resourceArn=log_group_arn, policyScope="RESOURCE"
    )["resourcePolicies"]
    assert len(described_after) == 1, f"expected exactly one resource policy, got {described_after}"
    stored_after_update = json.loads(described_after[0]["policyDocument"])
    assert stored_after_update == policy_doc_v2, (
        f"expected update with the correct revisionId to succeed, "
        f"expected {policy_doc_v2}, got {stored_after_update}"
    )

    # conflict: the revisionId the accepted update superseded no longer matches
    assert described_after[0]["revisionId"] != real_revision_id, (
        f"an accepted update must issue a new revisionId, still {real_revision_id!r}"
    )
    policy_doc_v3 = copy.deepcopy(policy_doc_v2)
    policy_doc_v3["Statement"][0]["Sid"] = "SupersededSid"
    code, msg = _error(
        lambda: logs.put_resource_policy(
            policyDocument=json.dumps(policy_doc_v3),
            resourceArn=log_group_arn,
            expectedRevisionId=real_revision_id,
        )
    )
    assert code == "OperationAbortedException", f"got {code!r} {msg!r}"
    assert msg == (
        "A conflicting operation is currently in progress against this resource. Please try again."
    ), f"got {msg!r}"
    stored_after_conflict = json.loads(
        logs.describe_resource_policies(resourceArn=log_group_arn, policyScope="RESOURCE")[
            "resourcePolicies"
        ][0]["policyDocument"]
    )
    assert stored_after_conflict == policy_doc_v2, (
        f"a superseded revisionId must not overwrite the policy, got {stored_after_conflict}"
    )


def _delete_resource_policy(logs, resource_arn):
    """Teardown: a policy written with expectedRevisionId can only be deleted by naming its
    current revision, so read it first and pass it."""
    for policy in logs.describe_resource_policies(
        resourceArn=resource_arn, policyScope="RESOURCE"
    )["resourcePolicies"]:
        logs.delete_resource_policy(resourceArn=resource_arn, expectedRevisionId=policy["revisionId"])


def _error(fn):
    """Call fn(); return its (error code, error message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
