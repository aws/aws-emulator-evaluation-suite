"""disassociate-last-permission-from-share-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "disassociate-last-permission-from-share-rejected"
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


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


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


def _wait_permission_status(ram, share_arn: str, permission_arn: str, status: str, timeout_s: float = 60.0):
    """Poll until exactly one permission is attached, matching arn+status.

    A replace transitions through a brief window where the old and new permission
    both appear (ASSOCIATING / DISASSOCIATING) before settling to a single entry.
    """
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        perms = ram.list_resource_share_permissions(resourceShareArn=share_arn)["permissions"]
        last = perms
        if len(perms) == 1 and perms[0]["arn"] == permission_arn and perms[0]["status"] == status:
            return perms[0]
        time.sleep(2.0)
    raise AssertionError(f"permission never reached arn={permission_arn!r} status={status!r}, last seen {last!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DisassociateResourceSharePermission refuses to remove the only permission a
    share's resources depend on, and the share keeps serving that permission
    unchanged until a replacement is associated first."""
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

    share_name = ctx.unique_name("sim2real-ram-lastperm-")
    share = ram.create_resource_share(
        name=share_name, resourceArns=[proj_arn], tags=[{"key": "sim2real", "value": CHECK}]
    )["resourceShare"]
    share_arn = share["resourceShareArn"]
    ctx.on_cleanup(
        _teardown(lambda: ram.delete_resource_share(resourceShareArn=share_arn), "UnknownResourceException")
    )

    _wait_association_status(ram, share_arn, proj_arn, "ASSOCIATED")

    managed_arn = "arn:aws:ram::aws:permission/AWSRAMDefaultPermissionCodeBuildProject"
    _wait_permission_status(ram, share_arn, managed_arn, "ASSOCIATED")

    ram.associate_resource_share_permission(resourceShareArn=share_arn, permissionArn=perm_arn, replace=True)
    _wait_permission_status(ram, share_arn, perm_arn, "ASSOCIATED")

    code, message = _error(
        lambda: ram.disassociate_resource_share_permission(resourceShareArn=share_arn, permissionArn=perm_arn)
    )
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code}: {message!r}"
    assert message == (
        f"The permission {perm_arn} cannot be disassociated because it is the last "
        "permission being used by resources of type codebuild:Project in the share."
    ), f"unexpected message {message!r}"

    # Effect absent: the refused disassociation left the permission attached and
    # ASSOCIATED, not in some half-removed state.
    unchanged = ram.list_resource_share_permissions(resourceShareArn=share_arn)["permissions"]
    assert len(unchanged) == 1 and unchanged[0]["arn"] == perm_arn, (
        f"expected {perm_arn!r} still the sole attached permission, got {unchanged!r}"
    )
    assert unchanged[0]["status"] == "ASSOCIATED", (
        f"expected the surviving permission to stay ASSOCIATED, got {unchanged[0]!r}"
    )

    # Positive control: swapping in a replacement permission first makes the share
    # healthy again, proving the refusal was about being the LAST permission, not a
    # general inability to change what a share attaches.
    ram.associate_resource_share_permission(resourceShareArn=share_arn, permissionArn=managed_arn, replace=True)
    restored = _wait_permission_status(ram, share_arn, managed_arn, "ASSOCIATED")
    assert restored["arn"] == managed_arn, f"expected the managed default restored, got {restored!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
