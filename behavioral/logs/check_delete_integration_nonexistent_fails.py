"""delete-integration-nonexistent-fails."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError
from botocore.parsers import ResponseParserError

from behavioral_harness import tags

CHECK = "delete-integration-nonexistent-fails"
GROUP = "error-semantics"
SERVICES = ["logs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:logs-integration")
def run(ctx) -> None:
    """DeleteIntegration on a never-created integration name raises ResourceNotFoundException, after
    a positive control shows DeleteIntegration really removes a real integration."""
    logs = ctx.client("logs")

    # CloudWatch Logs allows only one integration per account, so clear any existing one first.
    _clear_existing_integrations(logs)
    real_name = _create_real_integration(ctx, logs)

    logs.delete_integration(integrationName=real_name, force=True)
    post_delete_code, post_delete_message = _error(
        lambda: logs.get_integration(integrationName=real_name)
    )
    assert post_delete_code == "ResourceNotFoundException", (
        f"positive control: expected the just-deleted integration to be gone, got {post_delete_code}"
    )
    assert post_delete_message == f"Integration with name {real_name} does not exist.", (
        f"unexpected message: {post_delete_message!r}"
    )

    name = ctx.unique_name("sim2real-behav-integ-")

    get_code, get_message = _error(lambda: logs.get_integration(integrationName=name))
    assert get_code == "ResourceNotFoundException", f"expected fixture integration absent, got {get_code}"
    assert get_message == f"Integration with name {name} does not exist.", (
        f"unexpected message: {get_message!r}"
    )

    delete_code, delete_message = _error(lambda: logs.delete_integration(integrationName=name))
    assert delete_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException deleting a non-existent integration, got {delete_code}"
    )
    assert delete_message == f"Integration with name {name} does not exist.", (
        f"unexpected message: {delete_message!r}"
    )


# ===== helpers =====
def _error(fn):
    """Call fn(); return its error (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _status_of(logs, integration_name):
    try:
        return logs.get_integration(integrationName=integration_name).get("integrationStatus")
    except ResponseParserError:
        # GetIntegration's IntegrationDetails union is empty while PROVISIONING, which botocore's
        # parser rejects; treat that as "still provisioning".
        return "PROVISIONING"


def _clear_existing_integrations(logs):
    """Only one integration is allowed per account — evict whatever is there
    so this check's own positive control has room to create one."""
    for existing in logs.list_integrations().get("integrationSummaries", []):
        ename = existing["integrationName"]
        # Bounded wait for the leftover to leave PROVISIONING; the force delete below is
        # attempted either way and the empty-list poll is what must hold.
        deadline = time.monotonic() + 240
        while _status_of(logs, ename) not in ("ACTIVE", "FAILED", None):
            if time.monotonic() >= deadline:
                break
            time.sleep(2.0)
        try:
            logs.delete_integration(integrationName=ename, force=True)
        except ClientError:
            pass
    _poll_until(
        lambda: logs.list_integrations().get("integrationSummaries", []),
        lambda lst: lst == [],
        timeout_s=60,
        interval_s=3.0,
        description="account has no pre-existing integration",
    )


def _create_logs_service_role(ctx):
    """A REAL IAM role trusting logs.amazonaws.com, used as the integration's
    data-source role."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-dintg-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "logs.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real-behav-check", "Value": CHECK}],
    )

    def _teardown_role(rn=role_name, _iam=iam):
        try:
            _iam.delete_role_policy(RoleName=rn, PolicyName="allow-scheduled-query")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            _iam.delete_role(RoleName=rn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_teardown_role)
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="allow-scheduled-query",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["logs:StartQuery", "logs:GetQueryResults", "logs:StopQuery"],
                        "Resource": "*",
                    }
                ],
            }
        ),
    )
    account = ctx.client("sts").get_caller_identity()["Account"]
    return f"arn:aws:iam::{account}:role/{role_name}"


def _create_real_integration(ctx, logs) -> str:
    """Create a real OpenSearch integration and wait for it to leave
    PROVISIONING (DeleteIntegration is rejected mid-provisioning). Returns its
    name; registers a force-delete cleanup as a backstop."""
    role_arn = _create_logs_service_role(ctx)

    name = ctx.unique_name("sim2real-behav-integ-")
    logs.put_integration(
        integrationName=name,
        integrationType="OPENSEARCH",
        resourceConfig={
            "openSearchResourceConfig": {
                "dashboardViewerPrincipals": [role_arn],
                "dataSourceRoleArn": role_arn,
                "retentionDays": 1,
            }
        },
    )

    def _backstop_delete(_n=name, _logs=logs):
        try:
            _logs.delete_integration(integrationName=_n, force=True)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_backstop_delete)

    final_status = _poll_until(
        lambda: _status_of(logs, name),
        lambda s: s in ("ACTIVE", "FAILED"),
        timeout_s=540,
        interval_s=10.0,
        description="integration leaves PROVISIONING",
    )
    assert final_status in ("ACTIVE", "FAILED"), f"unexpected terminal status: {final_status!r}"
    got = logs.get_integration(integrationName=name)
    ctx.on_cleanup(lambda: _delete_collection(ctx, got))
    return name


def _delete_collection(ctx, got: dict) -> None:
    """Delete the OpenSearch Serverless collection an integration provisioned, which
    DeleteIntegration leaves in place; an already-deleted one is fine."""
    details = got.get("integrationDetails", {}).get("openSearchIntegrationDetails", {})
    arn = details.get("collection", {}).get("collectionArn")
    if not arn:
        return
    try:
        ctx.client("opensearchserverless").delete_collection(id=arn.rsplit("/", 1)[-1])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
