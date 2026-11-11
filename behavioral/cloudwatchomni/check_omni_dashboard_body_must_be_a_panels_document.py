"""omni-dashboard-body-must-be-a-panels-document."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "omni-dashboard-body-must-be-a-panels-document"
GROUP = 'dashboards'
SERVICES = ['cloudwatchomni']


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError ``fn()`` raises; a success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


@tags("axis:happy-path", "cap:c1", "concern:representation", "concern:negative-classes", "plane:control",
      "resource:account-singleton:cloudwatch-domain")
def run(ctx) -> None:
    """A dashboard body must be a {"panels": [...]} document with no extra top-level keys;
    a conforming body round-trips through CreateOmniDashboard/GetOmniDashboard/ListOmniDashboards
    and is gone once deleted.
    """
    cwo = ctx.client("cloudwatchomni")
    iam = ctx.client("iam")

    role_name = ctx.unique_name("sim2real-behav-cwo-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "cloudwatch.amazonaws.com"},
                        "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity"))

    domain_id = cwo.create_domain(
        name=ctx.unique_name("sim2real-behav-cwo-dom-"), identityProviders=["IAM"]
    )["domain"]["domainId"]
    ctx.on_cleanup(_teardown(lambda: cwo.delete_domain(domainId=domain_id), "ResourceNotFoundException"))

    space_id = cwo.create_space(
        name=ctx.unique_name("sim2real-behav-cwo-space-"), domainId=domain_id, dataAccessRoleArn=role_arn
    )["space"]["spaceId"]
    ctx.on_cleanup(_teardown(lambda: cwo.delete_space(spaceId=space_id),
                             "ResourceNotFoundException", "AccessDeniedException"))

    name = ctx.unique_name("sim2real-behav-cwo-dash-")
    code, message = _error(
        lambda: cwo.create_omni_dashboard(spaceId=space_id, name=name, body=json.dumps({"widgets": []}))
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}: {message!r}"
    assert message == (
        "panels: does not satisfy the 'required' constraint of the dashboard body schema; "
        "$: does not satisfy the 'additionalProperties' constraint of the dashboard body schema"
    ), f"unexpected message {message!r}"

    body = json.dumps({"panels": []})
    dashboard = cwo.create_omni_dashboard(spaceId=space_id, name=name, body=body, description="behavioral probe")[
        "omniDashboard"
    ]
    dashboard_id = dashboard["dashboardId"]
    ctx.on_cleanup(_teardown(
        lambda: cwo.delete_omni_dashboard(dashboardId=dashboard_id, spaceId=space_id),
        "ResourceNotFoundException",
    ))
    assert dashboard["body"] == body, f"expected body {body!r}, got {dashboard['body']!r}"

    got = cwo.get_omni_dashboard(dashboardId=dashboard_id, spaceId=space_id)["omniDashboard"]
    assert got["name"] == name, f"expected {name!r}, got {got['name']!r}"
    assert got["body"] == body, f"expected body {body!r}, got {got['body']!r}"

    found = {item["dashboardId"] for item in cwo.list_omni_dashboards(spaceId=space_id)["items"]}
    assert dashboard_id in found, f"expected {dashboard_id!r} in ListOmniDashboards, got {sorted(found)}"

    cwo.delete_omni_dashboard(dashboardId=dashboard_id, spaceId=space_id)
    code, _ = _error(lambda: cwo.get_omni_dashboard(dashboardId=dashboard_id, spaceId=space_id))
    assert code == "ResourceNotFoundException", f"expected gone after delete, got {code}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
