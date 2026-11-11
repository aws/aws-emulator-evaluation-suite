"""integration-lifecycle-transitions."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "integration-lifecycle-transitions"
GROUP = "state-machine"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:logs-integration")
def run(ctx) -> None:
    """PutIntegration creates an integration reflected in GetIntegration and ListIntegrations;
    DeleteIntegration removes it, and GetIntegration then fails with ResourceNotFoundException.
    """
    logs = ctx.client("logs")
    role_arn = _create_role(ctx, ["logs.amazonaws.com"])
    integration_name = ctx.unique_name("sim2real-integ-")

    # The account allows exactly one OpenSearch integration at a time, so drain any leftover.
    _drain_existing_integrations(logs)

    put_resp = logs.put_integration(
        integrationName=integration_name,
        integrationType="OPENSEARCH",
        resourceConfig={
            "openSearchResourceConfig": {
                "dataSourceRoleArn": role_arn,
                "dashboardViewerPrincipals": [role_arn],
                # Shortest retention accepted; the integration provisions billable resources.
                "retentionDays": 7,
            }
        },
    )
    ctx.on_cleanup(
        lambda: _safe_call(
            lambda: logs.delete_integration(integrationName=integration_name, force=True)
        )
    )

    assert put_resp["integrationName"] == integration_name, (
        f"PutIntegration echoed name {put_resp['integrationName']!r}, expected {integration_name!r}"
    )
    assert put_resp["integrationStatus"] in ("PROVISIONING", "ACTIVE"), (
        f"PutIntegration's own response reported status {put_resp['integrationStatus']!r} "
        "immediately after creation, expected PROVISIONING or ACTIVE"
    )

    # GetIntegration's response omits the type-specific details union member entirely while
    # PROVISIONING, which botocore's tagged-union parser rejects outright -- so the transition
    # out of PROVISIONING is observed via ListIntegrations (whose summary shape carries no such
    # union) before GetIntegration is ever called. Provisioning the real OpenSearch collection
    # and dashboards this integration type creates routinely takes several minutes.
    terminal_status = _poll_until(
        lambda: _status_by_list(logs, integration_name),
        lambda s: s in ("ACTIVE", "FAILED"),
        timeout_s=900.0,
        interval_s=10.0,
    )
    assert terminal_status == "ACTIVE", (
        f"integration {integration_name} left PROVISIONING as {terminal_status!r} instead of "
        "ACTIVE, for a role and config that grant everything PutIntegration asked for"
    )

    got = logs.get_integration(integrationName=integration_name)
    ctx.on_cleanup(lambda: _delete_integration_and_collection(ctx, logs, integration_name, got))
    assert got["integrationName"] == integration_name, (
        f"GetIntegration returned name {got['integrationName']!r}, expected {integration_name!r}"
    )
    assert got["integrationType"] == "OPENSEARCH", (
        f"GetIntegration returned type {got['integrationType']!r}, expected OPENSEARCH"
    )
    assert got["integrationStatus"] == terminal_status, (
        f"GetIntegration reported status {got['integrationStatus']!r}, but ListIntegrations had "
        f"already observed the terminal status {terminal_status!r} for the same integration"
    )

    def _integration_listed() -> bool:
        resp = logs.list_integrations()
        return any(
            i.get("integrationName") == integration_name
            for i in resp.get("integrationSummaries", [])
        )

    assert _integration_listed(), (
        f"integration {integration_name} reached a terminal status but is missing from "
        "ListIntegrations"
    )

    logs.delete_integration(integrationName=integration_name, force=True)
    _poll_until(
        _integration_listed,
        lambda found: found is False,
        timeout_s=30.0,
    )

    get_code, get_message = _error(lambda: logs.get_integration(integrationName=integration_name))
    assert get_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException from GetIntegration after DeleteIntegration, "
        f"got {get_code!r}"
    )
    assert get_message == f"Integration with name {integration_name} does not exist.", (
        f"unexpected GetIntegration message after DeleteIntegration: {get_message!r}"
    )


def _status_by_list(logs, integration_name: str) -> str | None:
    resp = logs.list_integrations()
    match = next(
        (
            i
            for i in resp.get("integrationSummaries", [])
            if i.get("integrationName") == integration_name
        ),
        None,
    )
    return match["integrationStatus"] if match is not None else None


def _drain_existing_integrations(logs) -> None:
    """Wait out and force-delete any integration already present (an account-wide singleton)."""
    drained = []
    for existing in logs.list_integrations().get("integrationSummaries", []):
        name = existing["integrationName"]
        drained.append(name)
        # Bounded wait for the leftover to leave PROVISIONING; the force delete is attempted
        # either way.
        deadline = time.monotonic() + 900.0
        while _status_by_list(logs, name) not in ("ACTIVE", "FAILED", None):
            if time.monotonic() >= deadline:
                break
            time.sleep(2.0)
        _safe_call(lambda name=name: logs.delete_integration(integrationName=name, force=True))
    _poll_until(
        lambda: [
            i["integrationName"]
            for i in logs.list_integrations().get("integrationSummaries", [])
            if i["integrationName"] in drained
        ],
        lambda remaining: remaining == [],
        timeout_s=60.0,
        interval_s=5.0,
    )


def _error(fn: Callable[[], Any]) -> tuple[str, str]:
    """Call fn(); return its error (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


def _safe_call(fn: Callable[[], Any]) -> None:
    try:
        fn()
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _delete_integration_and_collection(ctx, logs, integration_name: str, got: dict) -> None:
    """Delete the integration, then the OpenSearch Serverless collection it provisioned, which
    DeleteIntegration leaves in place."""
    _safe_call(lambda: logs.delete_integration(integrationName=integration_name, force=True))
    details = got.get("integrationDetails", {}).get("openSearchIntegrationDetails", {})
    arn = details.get("collection", {}).get("collectionArn")
    if arn:
        aoss = ctx.client("opensearchserverless")
        _safe_call(lambda: aoss.delete_collection(id=arn.rsplit("/", 1)[-1]))


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], timeout_s: float = 60.0, interval_s: float = 2.0) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _create_role(ctx, trust_services: list[str]) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-logs-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": trust_services}, "Action": "sts:AssumeRole"}
        ],
    }
    resp = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": "integration-lifecycle-transitions"}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))

    # The OpenSearch integration's data-source role must actually be able to provision the
    # collection/dashboard resources CloudWatch Logs creates on its behalf; an unpermissioned
    # role leaves the integration stuck FAILED, which would test the role instead of the
    # PutIntegration/GetIntegration/ListIntegrations/DeleteIntegration lifecycle.
    policy_arn = "arn:aws:iam::aws:policy/AmazonOpenSearchServiceFullAccess"
    iam.attach_role_policy(RoleName=name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: _safe_call(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=policy_arn)))
    return resp["Role"]["Arn"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
