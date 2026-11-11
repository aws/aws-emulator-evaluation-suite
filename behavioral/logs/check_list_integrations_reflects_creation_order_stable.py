"""list-integrations-reflects-creation-order-stable."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-integrations-reflects-creation-order-stable"
GROUP = "ordering"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:logs-integration")
def run(ctx) -> None:
    """Repeated ListIntegrations calls return identical results and, across delete then re-create,
    list only the latest live integration (the account allows one OpenSearch integration).
    """
    logs = ctx.client("logs")
    iam = ctx.client("iam")

    # One integration per account: clear a leftover from an interrupted run before starting.
    _drain_existing_integrations(logs)

    role_name = ctx.unique_name("sim2real-logs-integ-role-")
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
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/AmazonOpenSearchServiceFullAccess"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))

    def resource_config() -> dict:
        return {
            "openSearchResourceConfig": {
                "dataSourceRoleArn": role_arn,
                "dashboardViewerPrincipals": [role_arn],
                "retentionDays": 1,
            }
        }

    # IAM roles are eventually consistent, so the first PutIntegration is retried.
    name1 = ctx.unique_name("sim2real-logs-integ-a-")
    _put_integration_with_retry(ctx, logs, name1, resource_config(), own_names={name1})
    ctx.on_cleanup(lambda: _safe_delete_integration(logs, name1))

    # DeleteIntegration rejects a PROVISIONING integration even with force=True, so wait for a
    # terminal status (via ListIntegrations; GetIntegration's tagged union is unsafe to poll).
    status1 = _poll_until_terminal(logs, name1)
    assert status1 == "ACTIVE", (
        f"integration {name1} left PROVISIONING as {status1!r} instead of ACTIVE, for a "
        "role and config that grant everything PutIntegration asked for"
    )

    # Snapshots of a settled integration, so a status change between reads is not a difference.
    snapshots_a = [logs.list_integrations()["integrationSummaries"] for _ in range(3)]
    assert snapshots_a[0] == snapshots_a[1] == snapshots_a[2]
    names_a = [i["integrationName"] for i in snapshots_a[0]]
    assert name1 in names_a

    got1 = logs.get_integration(integrationName=name1)
    ctx.on_cleanup(lambda: _delete_collection(ctx, got1))
    logs.delete_integration(integrationName=name1, force=True)
    _poll_until(
        lambda: name1 not in _integration_names(logs),
        timeout_s=60.0,
        interval_s=3.0,
    )
    get_code, get_message = _error(lambda: logs.get_integration(integrationName=name1))
    assert get_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException from GetIntegration on the just-deleted "
        f"integration {name1!r}, got {get_code!r}"
    )
    assert get_message == f"Integration with name {name1} does not exist.", (
        f"unexpected GetIntegration message for the just-deleted integration: {get_message!r}"
    )

    # The quota slot frees some time after the deleted integration leaves the list, so
    # PutIntegration can still answer "Only a single integration is allowed per account".
    name2 = ctx.unique_name("sim2real-logs-integ-b-")
    _put_integration_with_retry(
        ctx, logs, name2, resource_config(), own_names={name1, name2}, timeout_s=180.0
    )
    ctx.on_cleanup(lambda: _safe_delete_integration(logs, name2))

    # Reach a terminal state here: cleanup's bounded delete would fail on a PROVISIONING one.
    status2 = _poll_until_terminal(logs, name2)
    assert status2 == "ACTIVE", (
        f"integration {name2} left PROVISIONING as {status2!r} instead of ACTIVE, for a "
        "role and config that grant everything PutIntegration asked for"
    )

    snapshots_b = [logs.list_integrations()["integrationSummaries"] for _ in range(3)]
    assert snapshots_b[0] == snapshots_b[1] == snapshots_b[2]
    names_b = [i["integrationName"] for i in snapshots_b[0]]
    assert name2 in names_b
    assert name1 not in names_b
    got2 = logs.get_integration(integrationName=name2)

    def _teardown_second() -> None:
        _safe_delete_integration(logs, name2)
        _delete_collection(ctx, got2)

    ctx.on_cleanup(_teardown_second)


def _is_quota_conflict(exc: Exception) -> bool:
    err = getattr(exc, "response", {}).get("Error", {})
    code = err.get("Code")
    message = err.get("Message", "")
    return code == "LimitExceededException" or (
        code == "ValidationException" and "single integration" in message.lower()
    )


def _put_integration_with_retry(
    ctx,
    logs,
    name: str,
    resource_config: dict,
    *,
    own_names: set[str],
    timeout_s: float = 60.0,
    interval_s: float = 5.0,
) -> None:
    """Retry PutIntegration through IAM propagation and quota release lag.

    A quota conflict is retried only while every listed integration is in ``own_names``.
    """
    deadline = time.monotonic() + timeout_s
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            logs.put_integration(
                integrationName=name, resourceConfig=resource_config, integrationType="OPENSEARCH"
            )
            return
        except Exception as exc:  # noqa: BLE001 -- inspect ClientError code below
            if _is_quota_conflict(exc):
                foreign = [n for n in _integration_names(logs) if n not in own_names]
                if foreign:
                    raise AssertionError(
                        f"account already has integration(s) {foreign!r} occupying the "
                        "1-integration-per-account quota; this check will not delete a "
                        "customer integration it did not create in order to make room"
                    ) from exc
            last_exc = exc
            time.sleep(interval_s)
    assert last_exc is not None
    raise last_exc


def _integration_names(logs) -> list[str]:
    return [i["integrationName"] for i in logs.list_integrations()["integrationSummaries"]]


def _drain_existing_integrations(logs, *, timeout_s: float = 900.0, interval_s: float = 10.0) -> None:
    drained = []
    for existing in logs.list_integrations().get("integrationSummaries", []):
        name = existing["integrationName"]
        drained.append(name)
        # Bounded wait to leave PROVISIONING; the force delete is attempted either way.
        deadline = time.monotonic() + timeout_s
        while _status_by_name(logs, name) not in ("ACTIVE", "FAILED", None):
            if time.monotonic() >= deadline:
                break
            time.sleep(interval_s)
        _safe_delete_integration(logs, name)
    _poll_until(
        lambda: not [n for n in _integration_names(logs) if n in drained],
        timeout_s=60.0,
        interval_s=3.0,
    )


def _status_by_name(logs, name: str) -> str | None:
    for i in logs.list_integrations().get("integrationSummaries", []):
        if i.get("integrationName") == name:
            return i.get("integrationStatus")
    return None


def _poll_until_terminal(logs, name: str, *, timeout_s: float = 900.0, interval_s: float = 10.0) -> str:
    deadline = time.monotonic() + timeout_s
    status: str | None = None
    while time.monotonic() < deadline:
        status = _status_by_name(logs, name)
        if status in ("ACTIVE", "FAILED"):
            return status
        time.sleep(interval_s)
    raise AssertionError(
        f"integration {name} did not leave PROVISIONING within {timeout_s}s (last status={status!r})"
    )


def _error(fn) -> tuple[str, str]:
    """Call fn(); return its error (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


def _safe_delete_integration(logs, name: str) -> None:
    """Force-delete an integration; an already-deleted one is fine, any other error raises."""
    try:
        logs.delete_integration(integrationName=name, force=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


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


def _poll_until(probe, *, timeout_s: float, interval_s: float) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if probe():
            return
        time.sleep(interval_s)
    raise AssertionError(f"condition never became true within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
