"""update-dashboard-rejects-invalid-body-and-keeps-stored-body."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-dashboard-rejects-invalid-body-and-keeps-stored-body"
GROUP = "dashboards"
SERVICES = ["cloudwatchomni"]


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


_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "cloudwatch.amazonaws.com"},
                    "Action": "sts:AssumeRole"}],
})


def _domain(ctx, cwo) -> dict:
    domain = cwo.create_domain(
        name=ctx.unique_name("sim2real-behav-cwo-dom-"), identityProviders=["IAM"]
    )["domain"]
    ctx.on_cleanup(_teardown(lambda: cwo.delete_domain(domainId=domain["domainId"]),
                             "ResourceNotFoundException"))
    return domain


def _space(ctx, cwo, domain_id: str) -> dict:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-cwo-role-")
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=_TRUST)["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity"))
    space = cwo.create_space(
        name=ctx.unique_name("sim2real-behav-cwo-space-"), domainId=domain_id, dataAccessRoleArn=role_arn
    )["space"]
    ctx.on_cleanup(_teardown(lambda: cwo.delete_space(spaceId=space["spaceId"]),
                             "ResourceNotFoundException", "AccessDeniedException"))
    return space


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control",
      "resource:account-singleton:cloudwatch-domain")
def run(ctx) -> None:
    """UpdateOmniDashboard refuses a body that is not JSON and a panel missing its required keys,
    each with its own message, and the stored body and description stay unchanged.
    """
    cwo = ctx.client("cloudwatchomni")
    domain_id = _domain(ctx, cwo)["domainId"]
    space_id = _space(ctx, cwo, domain_id)["spaceId"]
    body = json.dumps({"panels": []})
    did = cwo.create_omni_dashboard(
        spaceId=space_id, name=ctx.unique_name("sim2real-behav-cwo-dash-"), body=body, description="kept"
    )["omniDashboard"]["dashboardId"]
    ctx.on_cleanup(_teardown(lambda: cwo.delete_omni_dashboard(spaceId=space_id, dashboardId=did),
                             "ResourceNotFoundException"))

    code, message = _error(lambda: cwo.update_omni_dashboard(
        spaceId=space_id, dashboardId=did, body="not json", description="lost"))
    assert (code, message) == ("ValidationException", "dashboard body is not valid JSON at line 1 column 1"), (
        f"unexpected answer to a non-JSON body: {code}: {message!r}"
    )
    code, message = _error(lambda: cwo.update_omni_dashboard(
        spaceId=space_id, dashboardId=did, body=json.dumps({"panels": [{"x": 1}]})))
    assert code == "ValidationException", f"expected ValidationException, got {code}: {message!r}"
    assert message == (
        "panels[0].type: does not satisfy the 'required' constraint of the dashboard body schema; "
        "panels[0].layout: does not satisfy the 'required' constraint of the dashboard body schema; "
        "panels[0]: does not satisfy the 'additionalProperties' constraint of the dashboard body schema"
    ), f"unexpected message {message!r}"

    got = cwo.get_omni_dashboard(spaceId=space_id, dashboardId=did)["omniDashboard"]
    assert got["body"] == body, f"a refused update changed the body to {got['body']!r}"
    assert got.get("description") == "kept", f"a refused update changed the description to {got.get('description')!r}"
    cwo.update_omni_dashboard(spaceId=space_id, dashboardId=did, description="changed")
    after = cwo.get_omni_dashboard(spaceId=space_id, dashboardId=did)["omniDashboard"]
    assert (after["body"], after.get("description")) == (body, "changed"), (
        f"a description-only update must keep the body, got {after['body']!r} {after.get('description')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
