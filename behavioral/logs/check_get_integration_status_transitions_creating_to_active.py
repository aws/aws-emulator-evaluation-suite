"""get-integration-status-transitions-creating-to-active."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-integration-status-transitions-creating-to-active"
GROUP = "data-plane"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control", "resource:account-singleton:logs-integration")
def run(ctx) -> None:
    """PutIntegration (OpenSearch) starts PROVISIONING; ListIntegrations tracks it to ACTIVE, and
    GetIntegration, once provisioning ends, reports the same terminal status."""
    logs = ctx.client("logs")
    iam = ctx.client("iam")

    # CloudWatch Logs allows only one integration per account per region, so clear any leftover.
    _clear_preexisting_integrations(logs)

    role_name = ctx.unique_name("sim2real-logs-osis-role-")
    trust_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "logs.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust_policy,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _safe_delete_role(iam, role_name))
    managed_policy = "arn:aws:iam::aws:policy/AmazonOpenSearchServiceFullAccess"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=managed_policy)
    ctx.on_cleanup(lambda: _safe_detach_policy(iam, role_name, managed_policy))

    # IAM roles/policies take a few seconds to propagate before another service can assume them.
    _poll_until(lambda: _role_exists(iam, role_name), timeout_s=30.0, interval_s=3.0)

    integration_name = ctx.unique_name("sim2real-logs-osint-")
    put_resp = _put_integration_with_retry(logs, integration_name, role_arn)
    ctx.on_cleanup(lambda: _safe_delete_integration(logs, integration_name))

    first_status = put_resp["integrationStatus"]
    assert first_status == "PROVISIONING", (
        f"expected a freshly created integration to start PROVISIONING, got {first_status!r}"
    )

    final_status = _poll_until_left_provisioning(
        logs, integration_name, timeout_s=900.0, interval_s=15.0
    )
    assert final_status == "ACTIVE", f"integration never reached ACTIVE (status={final_status})"

    # GetIntegration is safe only now: while PROVISIONING its empty details union fails
    # botocore's tagged-union parser.
    get_resp = logs.get_integration(integrationName=integration_name)
    assert get_resp["integrationStatus"] == "ACTIVE", (
        f"GetIntegration disagreed with the ListIntegrations-observed terminal status: "
        f"{get_resp['integrationStatus']!r} != 'ACTIVE'"
    )

    summaries = logs.list_integrations(integrationNamePrefix=integration_name)["integrationSummaries"]
    matching = [s for s in summaries if s["integrationName"] == integration_name]
    assert matching, "ListIntegrations did not show the integration after it became ACTIVE"
    assert matching[0]["integrationStatus"] == "ACTIVE"


def _clear_preexisting_integrations(logs) -> None:
    """CloudWatch Logs allows only one integration per account per region. Wait any
    pre-existing one out of PROVISIONING (DeleteIntegration is rejected mid-provisioning)
    and force-delete it, then confirm the account is clear."""
    drained = []
    for existing in logs.list_integrations().get("integrationSummaries", []):
        name = existing["integrationName"]
        drained.append(name)
        # Bounded wait for the leftover to leave PROVISIONING; the force delete is attempted
        # either way.
        wait_until = time.monotonic() + 240.0
        while existing.get("integrationStatus") == "PROVISIONING" and time.monotonic() < wait_until:
            time.sleep(2)
            existing = next(
                (
                    i
                    for i in logs.list_integrations().get("integrationSummaries", [])
                    if i["integrationName"] == name
                ),
                {},
            )
        try:
            logs.delete_integration(integrationName=name, force=True)
        except ClientError:
            pass
    deadline = time.monotonic() + 60.0
    while time.monotonic() < deadline:
        remaining = [
            i["integrationName"]
            for i in logs.list_integrations().get("integrationSummaries", [])
            if i["integrationName"] in drained
        ]
        if not remaining:
            return
        time.sleep(3.0)
    raise AssertionError("account still has a pre-existing CloudWatch Logs integration after attempting to clear it")


def _put_integration_with_retry(
    logs, integration_name: str, role_arn: str, timeout_s: float = 60.0, interval_s: float = 5.0
) -> dict:
    """A freshly attached IAM role policy can take a few seconds to propagate before
    another service can rely on it; retry the dependent-service errors that eventual
    consistency can trigger before treating the failure as terminal."""
    deadline = time.monotonic() + timeout_s
    last_exc: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            return logs.put_integration(
                integrationName=integration_name,
                integrationType="OPENSEARCH",
                resourceConfig={
                    "openSearchResourceConfig": {
                        "dataSourceRoleArn": role_arn,
                        "dashboardViewerPrincipals": [role_arn],
                        "retentionDays": 7,
                    }
                },
            )
        except ClientError as exc:
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(
        f"PutIntegration kept failing even after retrying for IAM propagation: {last_exc}"
    ) from last_exc


def _poll_until_left_provisioning(logs, integration_name: str, timeout_s: float, interval_s: float) -> Any:
    """Poll ListIntegrations until the integration leaves PROVISIONING; GetIntegration's empty
    details union during provisioning fails botocore's tagged-union parser."""
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        summaries = logs.list_integrations(integrationNamePrefix=integration_name)["integrationSummaries"]
        match = next((s for s in summaries if s["integrationName"] == integration_name), None)
        if match is not None:
            status = match["integrationStatus"]
            if status != "PROVISIONING":
                return status
        time.sleep(interval_s)
    raise AssertionError(f"integration {integration_name} did not leave PROVISIONING in time (status={status!r})")


def _role_exists(iam, role_name: str) -> bool:
    try:
        iam.get_role(RoleName=role_name)
        return True
    except Exception:
        return False


def _safe_delete_role(iam, role_name: str) -> None:
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _safe_detach_policy(iam, role_name: str, policy_arn: str) -> None:
    try:
        iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _safe_delete_integration(logs, integration_name: str) -> None:
    try:
        logs.delete_integration(integrationName=integration_name, force=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _poll_until(predicate: Callable[[], bool], timeout_s: float, interval_s: float) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval_s)
    return predicate()


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
