"""dashboard-names-are-not-unique-within-a-space."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "dashboard-names-are-not-unique-within-a-space"
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


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control",
      "resource:account-singleton:cloudwatch-domain")
def run(ctx) -> None:
    """Two CreateOmniDashboard calls with the same name in one space both succeed with distinct ids,
    both are listed, and deleting one leaves the other readable.
    """
    cwo = ctx.client("cloudwatchomni")
    domain_id = _domain(ctx, cwo)["domainId"]
    space_id = _space(ctx, cwo, domain_id)["spaceId"]
    name = ctx.unique_name("sim2real-behav-cwo-dash-")
    body = json.dumps({"panels": []})
    made = []
    for _ in range(2):
        did = cwo.create_omni_dashboard(spaceId=space_id, name=name, body=body)["omniDashboard"]["dashboardId"]
        ctx.on_cleanup(_teardown(lambda d=did: cwo.delete_omni_dashboard(spaceId=space_id, dashboardId=d),
                                 "ResourceNotFoundException"))
        made.append(did)
    assert made[0] != made[1], "two creates must mint two dashboards"

    listed = {d["dashboardId"]: d["name"] for page in cwo.get_paginator("list_omni_dashboards").paginate(spaceId=space_id)
              for d in page["items"]}
    assert {k: listed.get(k) for k in made} == {made[0]: name, made[1]: name}, (
        f"expected both dashboards listed under {name!r}, got {[listed.get(k) for k in made]!r}"
    )
    cwo.delete_omni_dashboard(spaceId=space_id, dashboardId=made[0])
    code, message = _error(lambda: cwo.get_omni_dashboard(spaceId=space_id, dashboardId=made[0]))
    assert (code, message) == ("ResourceNotFoundException", f"Dashboard not found: {made[0]}"), (
        f"expected the deleted dashboard gone, got {code}: {message!r}"
    )
    assert cwo.get_omni_dashboard(spaceId=space_id, dashboardId=made[1])["omniDashboard"]["name"] == name, (
        "the namesake must survive"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
