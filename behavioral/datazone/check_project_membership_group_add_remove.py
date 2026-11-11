"""project-membership-group-add-remove."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "project-membership-group-add-remove"
GROUP = "data-plane"
SERVICES = ["datazone"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateProjectMembership for a group member on a domain without IAM Identity Center or an
    external IdP has no group profile to resolve, so it is rejected with ResourceNotFoundException
    and no membership is created."""
    dz = ctx.client("datazone")
    domain = _create_domain(ctx)
    project = _create_project(ctx, domain["id"])

    baseline = dz.list_project_memberships(domainIdentifier=domain["id"], projectIdentifier=project["id"])[
        "members"
    ]
    baseline_count = len(baseline)

    group_id = ctx.unique_name("sim2real-pm-group-")
    code, message = _expect_client_error(
        lambda: dz.create_project_membership(
            domainIdentifier=domain["id"],
            projectIdentifier=project["id"],
            member={"groupIdentifier": group_id},
            designation="PROJECT_CATALOG_VIEWER",
        )
    )
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException adding a group to an unfederated domain, got {code}: {message}"
    )
    expected = (
        f"Group profile '{group_id}' not found for domain '{domain['id']}', "
        f"profile creation is only valid for implicit domain"
    )
    assert message == expected, (
        f"expected the SSO/implicit-domain group-profile refusal {expected!r}, got: {message!r}"
    )

    members = dz.list_project_memberships(domainIdentifier=domain["id"], projectIdentifier=project["id"])[
        "members"
    ]
    assert len(members) == baseline_count, (
        f"expected {baseline_count} members after the rejected add, got {len(members)}: {members}"
    )
    matches = [m for m in members if m["memberDetails"].get("group", {}).get("groupId") == group_id]
    assert not matches, f"expected no member for {group_id} after the rejected add, found {matches}"


def _expect_client_error(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError("expected a ClientError, call unexpectedly succeeded")


# ===== helpers =====
def _safe(fn, deadline_s=60.0):
    """Teardown: a resource already gone is fine; ConflictException (a dependent resource is still
    being released) is retried to a deadline; every other error raises."""
    def _wrapped():
        from botocore.exceptions import ClientError

        deadline = time.monotonic() + deadline_s
        while True:
            try:
                fn()
                return
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code")
                if code in ("ResourceNotFoundException", "NoSuchEntity"):
                    return
                if code != "ConflictException" or time.monotonic() >= deadline:
                    raise
            time.sleep(2)

    return _wrapped


def _create_domain(ctx):
    dz = ctx.client("datazone")
    role_arn = _create_domain_execution_role(ctx)
    name = ctx.unique_name("sim2real-dz-domain-")
    created = _create_domain_call(dz, name, role_arn)
    domain_id = created["id"]
    ctx.on_cleanup(
        _safe(lambda: dz.delete_domain(identifier=domain_id, cascadeDelete=True))
    )
    return _wait_domain_available(ctx, domain_id)


def _create_domain_execution_role(ctx):

    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-dz-exec-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "datazone.amazonaws.com"},
                "Action": ["sts:AssumeRole", "sts:TagSession", "sts:SetContext"],
            }
        ],
    }
    role = _create_role_with_retry(iam, role_name, trust_policy, CHECK)
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(_safe(lambda: iam.delete_role(RoleName=role_name)))
    return role_arn


def _create_role_with_retry(iam, role_name, trust_policy, check_tag, timeout_s=60.0):
    import json

    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return iam.create_role(
                RoleName=role_name,
                AssumeRolePolicyDocument=json.dumps(trust_policy),
                Tags=[{"Key": "sim2real-check", "Value": check_tag}],
            )
        except Exception as exc:
            last_exc = exc
            time.sleep(3)
    raise last_exc


def _create_domain_call(dz, name, role_arn, timeout_s=60.0):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return dz.create_domain(
                name=name, domainExecutionRole=role_arn, tags={"sim2real-check": CHECK}
            )
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("ValidationException", "AccessDeniedException"):
                last_exc = exc
                time.sleep(3)
                continue
            raise
    raise last_exc


def _wait_domain_available(ctx, domain_id, timeout_s=900.0):
    dz = ctx.client("datazone")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = dz.get_domain(identifier=domain_id)
        last = resp
        if resp["status"] == "AVAILABLE":
            return resp
        if resp["status"] == "CREATION_FAILED":
            raise AssertionError(f"domain {domain_id} creation failed: {resp}")
        time.sleep(5)
    raise AssertionError(f"domain {domain_id} did not become AVAILABLE in time: {last}")


def _create_project(ctx, domain_id, name=None, domain_unit_id=None):
    dz = ctx.client("datazone")
    name = name or ctx.unique_name("sim2real-dz-proj-")
    kwargs = {"domainIdentifier": domain_id, "name": name, "resourceTags": {"sim2real-check": CHECK}}
    if domain_unit_id:
        kwargs["domainUnitId"] = domain_unit_id
    resp = dz.create_project(**kwargs)
    project_id = resp["id"]
    ctx.on_cleanup(
        _safe(
            lambda: dz.delete_project(
                domainIdentifier=domain_id, identifier=project_id, skipDeletionCheck=True
            )
        )
    )
    return resp


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
