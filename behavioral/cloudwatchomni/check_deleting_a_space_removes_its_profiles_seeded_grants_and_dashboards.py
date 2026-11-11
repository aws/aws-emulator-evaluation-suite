"""deleting-a-space-removes-its-profiles-seeded-grants-and-dashboards."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deleting-a-space-removes-its-profiles-seeded-grants-and-dashboards"
GROUP = "spaces"
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
    """DeleteSpace succeeds while the space holds a customer profile and a dashboard; afterwards the
    space lists no grants and reading the space, its profile or its dashboard is denied.
    """
    cwo = ctx.client("cloudwatchomni")
    domain_id = _domain(ctx, cwo)["domainId"]
    space_id = _space(ctx, cwo, domain_id)["spaceId"]
    profile_id = cwo.create_access_profile(
        spaceId=space_id, name=ctx.unique_name("sim2real-behav-cwo-prof-"))["accessProfile"]["profileId"]
    dashboard_id = cwo.create_omni_dashboard(
        spaceId=space_id, name=ctx.unique_name("sim2real-behav-cwo-dash-"), body=json.dumps({"panels": []})
    )["omniDashboard"]["dashboardId"]
    seeded = [g for page in cwo.get_paginator("list_access_grants").paginate(spaceId=space_id) for g in page["items"]]
    assert len(seeded) == 2, f"expected the two seeded grants before the delete, got {len(seeded)}"

    cwo.delete_space(spaceId=space_id)
    left = [g for page in cwo.get_paginator("list_access_grants").paginate(spaceId=space_id) for g in page["items"]]
    assert left == [], f"expected no grants for the deleted space, got {len(left)}"
    for label, read in (
        ("space", lambda: cwo.get_space(spaceId=space_id)),
        ("profile", lambda: cwo.get_access_profile(spaceId=space_id, profileId=profile_id)),
        ("dashboard", lambda: cwo.get_omni_dashboard(spaceId=space_id, dashboardId=dashboard_id)),
    ):
        code, message = _error(read)
        assert (code, message) == ("AccessDeniedException", "Authorization failed"), (
            f"expected reading the deleted space's {label} to be denied, got {code}: {message!r}"
        )
    assert [d["domainId"] for d in cwo.list_domains()["items"]] == [domain_id], "the domain must outlive its space"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
