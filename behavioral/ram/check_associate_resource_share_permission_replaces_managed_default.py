"""associate-resource-share-permission-replaces-managed-default."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "associate-resource-share-permission-replaces-managed-default"
GROUP = "permission-association"
SERVICES = ["ram"]


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _delete_role(iam, role_name: str) -> None:
    try:
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            try:
                iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_service_role(ctx) -> str:
    """Mint a real CodeBuild-assumable IAM service role (so CreateProject validates)."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-ram-cbrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "codebuild.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Path="/sim2real/",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_role(iam, role_name))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="codebuild-inline",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                "Resource": "*",
            }],
        }),
    )
    return resp["Role"]["Arn"]


def _create_project(cb, ctx, role_arn: str):
    """Create a uniquely-named TEST project, retrying through IAM role propagation."""
    name = ctx.unique_name("sim2real-ram-proj-")
    kwargs = dict(
        name=name,
        source={
            "type": "NO_SOURCE",
            "buildspec": "version: 0.2\nphases:\n  build:\n    commands:\n      - echo hi\n",
        },
        artifacts={"type": "NO_ARTIFACTS"},
        environment={
            "type": "LINUX_CONTAINER",
            "image": "aws/codebuild/standard:7.0",
            "computeType": "BUILD_GENERAL1_SMALL",
        },
        serviceRole=role_arn,
        tags=[{"key": "sim2real", "value": CHECK}],
    )
    deadline = time.monotonic() + 75
    while True:
        try:
            resp = cb.create_project(**kwargs)
            break
        except ClientError as exc:
            err = exc.response.get("Error", {})
            msg = (err.get("Message") or "").lower()
            transient_role = err.get("Code") == "InvalidInputException" and (
                "assume" in msg or "not authorized" in msg
            )
            if transient_role and time.monotonic() < deadline:
                time.sleep(3)
                continue
            raise
    proj = resp["project"]
    ctx.on_cleanup(lambda: cb.delete_project(name=proj["name"]))
    return proj


def _wait_association_status(ram, share_arn: str, resource_arn: str, status: str, timeout_s: float = 60.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        pages = ram.get_paginator("get_resource_share_associations").paginate(
            associationType="RESOURCE", resourceShareArns=[share_arn], resourceArn=resource_arn
        )
        associations = [a for page in pages for a in page["resourceShareAssociations"]]
        assert len(associations) == 1, f"expected exactly 1 association, got {associations!r}"
        last = associations[0]["status"]
        if last == status:
            return associations[0]
        time.sleep(2.0)
    raise AssertionError(f"association never reached {status!r}, last seen {last!r}")


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A customer-managed permission associated with replace=True swaps out the
    AWS-managed default permission a real resource arrived with, entirely."""
    cb = ctx.client("codebuild")
    ram = ctx.client("ram")

    perm_name = ctx.unique_name("sim2real-ram-cmp-")
    cmp_ = ram.create_permission(
        name=perm_name,
        resourceType="codebuild:Project",
        policyTemplate=json.dumps({"Effect": "Allow", "Action": ["codebuild:BatchGetProjects"]}),
        tags=[{"key": "sim2real", "value": CHECK}],
    )["permission"]
    perm_arn = cmp_["arn"]
    ctx.on_cleanup(
        _teardown(lambda: ram.delete_permission(permissionArn=perm_arn), "UnknownResourceException")
    )

    role_arn = _create_service_role(ctx)
    proj = _create_project(cb, ctx, role_arn)
    proj_arn = proj["arn"]

    share_name = ctx.unique_name("sim2real-ram-cmpshare-")
    share = ram.create_resource_share(
        name=share_name, resourceArns=[proj_arn], tags=[{"key": "sim2real", "value": CHECK}]
    )["resourceShare"]
    share_arn = share["resourceShareArn"]
    ctx.on_cleanup(
        _teardown(lambda: ram.delete_resource_share(resourceShareArn=share_arn), "UnknownResourceException")
    )

    _wait_association_status(ram, share_arn, proj_arn, "ASSOCIATED")

    before = ram.list_resource_share_permissions(resourceShareArn=share_arn)["permissions"]
    assert len(before) == 1, f"expected exactly 1 permission attached at creation, got {before!r}"
    assert before[0]["arn"] == "arn:aws:ram::aws:permission/AWSRAMDefaultPermissionCodeBuildProject", (
        f"expected the AWS-managed default to auto-attach, got {before[0]['arn']!r}"
    )

    result = ram.associate_resource_share_permission(
        resourceShareArn=share_arn, permissionArn=perm_arn, replace=True
    )
    assert result["returnValue"] is True, f"expected returnValue True, got {result['returnValue']!r}"

    deadline = time.monotonic() + 60.0
    after = None
    while time.monotonic() < deadline:
        after = ram.list_resource_share_permissions(resourceShareArn=share_arn)["permissions"]
        if len(after) == 1 and after[0]["status"] == "ASSOCIATED":
            break
        time.sleep(2.0)
    assert after is not None and len(after) == 1, f"expected exactly 1 permission attached after replace, got {after!r}"
    assert after[0]["arn"] == perm_arn, (
        f"expected the customer-managed permission {perm_arn!r} attached, got {after[0]['arn']!r}"
    )
    assert after[0]["status"] == "ASSOCIATED", f"expected ASSOCIATED, got {after[0]['status']!r}"

    associations = ram.list_permission_associations(permissionArn=perm_arn)["permissions"]
    matching = [a for a in associations if a["resourceShareArn"] == share_arn]
    assert len(matching) == 1, (
        f"expected the share to appear in the permission's own association list, got {associations!r}"
    )
    assert matching[0]["status"] == "ASSOCIATED", (
        f"expected the association status ASSOCIATED, got {matching[0]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
