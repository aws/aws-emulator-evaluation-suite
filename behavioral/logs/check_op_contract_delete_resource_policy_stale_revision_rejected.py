"""op-contract-delete-resource-policy-stale-revision-rejected."""

from __future__ import annotations

import json
import random
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-delete-resource-policy-stale-revision-rejected"
GROUP = "error-semantics"
SERVICES = ["logs"]


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
    "resource:account-singleton:logs-resource-policy",
)
def run(ctx) -> None:
    """DeleteResourcePolicy with a stale (superseded but AWS-issued) expectedRevisionId on a
    resource-scoped policy is rejected with OperationAbortedException; the same delete with the
    current revision succeeds and the policy disappears from DescribeResourcePolicies."""
    logs = ctx.client("logs")
    group_name = ctx.unique_name("sim2real-behav-rp-lg-")
    policy_name = ctx.unique_name("sim2real-behav-rp-")

    # Resource-policy mutations contend account-wide with OperationAbortedException. Each mutating
    # call gets its own retry budget so one call's contention cannot starve another's; 4 calls x
    # 45s plus 3 polls x 15s stays under the 300s per-check timeout.
    _CALL_BUDGET_S = 45

    logs.create_log_group(logGroupName=group_name, tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group_name))
    described = logs.describe_log_groups(logGroupNamePrefix=group_name)
    raw_log_group_arn = next(
        g["arn"] for g in described["logGroups"] if g["logGroupName"] == group_name
    )

    # DescribeLogGroups ARNs may carry a uniqueness suffix ("...:log-group:<name>:AbCdEf") that
    # PutResourcePolicy rejects as an invalid resourceArn; rebuild the classic ARN (log group
    # names never contain ':').
    _parts = raw_log_group_arn.split(":")
    log_group_arn = ":".join(_parts[:7]) if len(_parts) > 7 else raw_log_group_arn

    # expectedRevisionId is enforced only for RESOURCE-scoped policies; an account-scoped policy
    # ignores a stale value, so scope the policy to this log group's ARN.
    policy_document = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "Sim2RealBehavioral",
                    "Effect": "Allow",
                    "Principal": {"Service": ["route53.amazonaws.com"]},
                    "Action": "logs:PutLogEvents",
                    "Resource": log_group_arn,
                }
            ],
        }
    )

    # PutResourcePolicy rejects policyName together with resourceArn; CloudWatch Logs assigns
    # the name of a resource-scoped policy itself.
    put_resp = _put_resource_policy_retrying(
        logs,
        deadline=time.time() + _CALL_BUDGET_S,
        policyDocument=policy_document,
        resourceArn=log_group_arn,
    )
    real_policy_name = (
        put_resp.get("resourcePolicy", {}).get("policyName") or policy_name
    )
    ctx.on_cleanup(lambda: _delete_if_exists(logs, resource_arn=log_group_arn))

    # DescribeResourcePolicies is eventually consistent after PutResourcePolicy, and the policyName
    # it reports may differ from the one PutResourcePolicy echoed, so match on resourceArn
    # (tolerating a stored trailing ":*") and read the name and revision from the listed entry.
    def _list_resource_policies():
        resp = logs.describe_resource_policies(policyScope="RESOURCE")
        return resp.get("resourcePolicies", [])

    def _find_by_arn(policies, arn):
        for p in policies:
            p_arn = (p.get("resourceArn") or "").rstrip(":*")
            if p_arn == arn.rstrip(":*"):
                return p
        return None

    policies = _list_resource_policies()
    matched = _find_by_arn(policies, log_group_arn)
    deadline = time.time() + 15
    while matched is None and time.time() < deadline:
        time.sleep(2)
        policies = _list_resource_policies()
        matched = _find_by_arn(policies, log_group_arn)
    assert matched is not None, "resource policy not visible after PutResourcePolicy"

    real_policy_name = matched.get("policyName") or real_policy_name
    old_revision = matched.get("revisionId")
    assert old_revision, (
        "DescribeResourcePolicies did not report a revisionId for the resource-scoped policy"
    )

    # A synthesized revision id is rejected as invalid (InvalidParameterException), not stale, so
    # bump the real revision with a second put and use the superseded AWS-issued id.
    bumped_policy_document = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "Sim2RealBehavioralBumped",
                    "Effect": "Allow",
                    "Principal": {"Service": ["route53.amazonaws.com"]},
                    "Action": "logs:PutLogEvents",
                    "Resource": log_group_arn,
                }
            ],
        }
    )
    _put_resource_policy_retrying(
        logs,
        deadline=time.time() + _CALL_BUDGET_S,
        policyDocument=bumped_policy_document,
        resourceArn=log_group_arn,
        expectedRevisionId=old_revision,
    )

    policies = _list_resource_policies()
    matched = _find_by_arn(policies, log_group_arn)
    deadline = time.time() + 15
    while (
        matched is None or matched.get("revisionId") == old_revision
    ) and time.time() < deadline:
        time.sleep(2)
        policies = _list_resource_policies()
        matched = _find_by_arn(policies, log_group_arn)
    assert matched is not None, (
        "resource policy not visible after updating PutResourcePolicy"
    )
    real_policy_name = matched.get("policyName") or real_policy_name
    new_revision = matched.get("revisionId")
    assert new_revision and new_revision != old_revision, (
        "expected revisionId to change after a second PutResourcePolicy"
    )

    # resourceArn alone identifies a resource-scoped policy (policyName must be omitted). AWS
    # reports the revision conflict as OperationAbortedException, so this call is made once,
    # without the contention retry.
    code, message = _error(
        lambda: logs.delete_resource_policy(
            resourceArn=log_group_arn,
            expectedRevisionId=old_revision,
        )
    )
    assert code == "OperationAbortedException", (
        f"expected OperationAbortedException, got {code}"
    )
    assert message == (
        "A conflicting operation is currently in progress against this resource. "
        "Please try again."
    ), f"unexpected message: {message!r}"

    # Positive control: the same delete with the current revision is accepted.
    _delete_resource_policy_retrying(
        logs,
        deadline=time.time() + _CALL_BUDGET_S,
        resourceArn=log_group_arn,
        expectedRevisionId=new_revision,
    )
    policies = _list_resource_policies()
    matched = _find_by_arn(policies, log_group_arn)
    deadline = time.time() + 15
    while matched is not None and time.time() < deadline:
        time.sleep(2)
        policies = _list_resource_policies()
        matched = _find_by_arn(policies, log_group_arn)
    assert matched is None, "resource policy still present after delete"


def _put_resource_policy_retrying(logs, deadline=None, **kwargs):
    """PutResourcePolicy, retrying the transient account-wide OperationAbortedException with
    jittered backoff until `deadline`, a per-call budget (60s when omitted)."""
    if deadline is None:
        deadline = time.time() + 60
    delay = 2.0
    while True:
        try:
            return logs.put_resource_policy(**kwargs)
        except ClientError as exc:
            if (
                exc.response["Error"]["Code"] != "OperationAbortedException"
                or time.time() >= deadline
            ):
                raise
            time.sleep(
                min(delay + random.uniform(0, delay), max(deadline - time.time(), 0))
            )
            delay = min(delay * 2, 15.0)


def _delete_resource_policy_retrying(logs, deadline=None, **kwargs):
    """DeleteResourcePolicy with the same OperationAbortedException retry as
    _put_resource_policy_retrying; other errors re-raise immediately."""
    if deadline is None:
        deadline = time.time() + 60
    delay = 2.0
    while True:
        try:
            return logs.delete_resource_policy(**kwargs)
        except ClientError as exc:
            if (
                exc.response["Error"]["Code"] != "OperationAbortedException"
                or time.time() >= deadline
            ):
                raise
            time.sleep(
                min(delay + random.uniform(0, delay), max(deadline - time.time(), 0))
            )
            delay = min(delay * 2, 15.0)


def _error(fn):
    """Call fn(); return its error (code, message). An unexpected success raises, so an
    over-permissive target is not reported as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(
        f"expected rejection, but the call SUCCEEDED and returned {result!r}"
    )


def _delete_if_exists(logs, policy_name=None, resource_arn=None):
    try:
        # DeleteResourcePolicy rejects specifying both policyName and resourceArn; prefer
        # resourceArn (unambiguous for resource-scoped policies) when both are available.
        if resource_arn:
            # A resource-scoped delete requires the policy's current revision id.
            current = [
                p
                for p in logs.describe_resource_policies(policyScope="RESOURCE").get(
                    "resourcePolicies", []
                )
                if (p.get("resourceArn") or "").rstrip(":*") == resource_arn.rstrip(":*")
            ]
            if not current:
                return
            kwargs = {
                "resourceArn": resource_arn,
                "expectedRevisionId": current[0]["revisionId"],
            }
        else:
            kwargs = {"policyName": policy_name}
        # Cleanup can race other resource-policy mutations too, so it retries on its own budget.
        _delete_resource_policy_retrying(logs, deadline=time.time() + 60, **kwargs)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
