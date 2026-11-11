"""deployment-group-ec2-tag-filters-and-tag-set-conflict."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "deployment-group-ec2-tag-filters-and-tag-set-conflict"
GROUP = 'overly-permissive'
SERVICES = ['codedeploy']

TAG_FILTER = {"Key": "sim2real:env", "Value": "behav", "Type": "KEY_AND_VALUE"}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ec2TagFilters and ec2TagSet are each accepted alone, but together are refused with
    InvalidEC2TagCombinationException and no group is created."""
    cd = ctx.client("codedeploy")
    app = _create_application(ctx, compute_platform="Server")

    # Control A: ec2TagFilters alone. This also proves the service role is assumable,
    # so an InvalidRoleException on the negative below would be a real mismatch and
    # not a propagation artifact.
    ok_filters = _create_dg_control(ctx, app, ec2TagFilters=[TAG_FILTER])
    echoed = cd.get_deployment_group(
        applicationName=app, deploymentGroupName=ok_filters
    )["deploymentGroupInfo"]
    assert echoed.get("ec2TagFilters") == [TAG_FILTER], (
        f"ec2TagFilters must round-trip verbatim, got {echoed.get('ec2TagFilters')!r}"
    )
    assert not echoed.get("ec2TagSet"), (
        f"a group created with ec2TagFilters must not report an ec2TagSet: {echoed!r}"
    )

    # Control B: ec2TagSet alone.
    ok_tagset = _create_dg_control(
        ctx, app, ec2TagSet={"ec2TagSetList": [[TAG_FILTER]]}
    )
    echoed_set = cd.get_deployment_group(
        applicationName=app, deploymentGroupName=ok_tagset
    )["deploymentGroupInfo"]
    assert echoed_set.get("ec2TagSet", {}).get("ec2TagSetList") == [[TAG_FILTER]], (
        f"ec2TagSet must round-trip verbatim, got {echoed_set.get('ec2TagSet')!r}"
    )

    before = _dg_names(cd, app)
    assert set(before) == {ok_filters, ok_tagset}, before

    # Break exactly one thing: supply both.
    bad = ctx.unique_name("sim2real-behav-cd-dg-both-")
    code, message = _error(
        lambda: cd.create_deployment_group(
            applicationName=app,
            deploymentGroupName=bad,
            deploymentConfigName="CodeDeployDefault.OneAtATime",
            serviceRoleArn=_create_service_role(ctx),
            ec2TagFilters=[TAG_FILTER],
            ec2TagSet={"ec2TagSetList": [[TAG_FILTER]]},
        )
    )
    assert code == "InvalidEC2TagCombinationException", (
        f"supplying both ec2TagFilters and ec2TagSet must raise "
        f"InvalidEC2TagCombinationException, got {code!r}"
    )
    assert message == (
        "The request specified both Ec2TagFilters and Ec2TagSet, but only one of these data "
        "types can be used in a single call. Remove one tag specification type, and then try "
        "again."
    ), message

    # The effect is absent.
    after = _dg_names(cd, app)
    assert after == before, (
        f"a refused CreateDeploymentGroup must not change ListDeploymentGroups: "
        f"{before!r} -> {after!r}"
    )
    missing, missing_message = _error(
        lambda: cd.get_deployment_group(applicationName=app, deploymentGroupName=bad)
    )
    assert missing == "DeploymentGroupDoesNotExistException", (
        f"the refused group {bad} must not exist; GetDeploymentGroup answered "
        f"{missing!r}"
    )
    assert missing_message == f"No Deployment Group found for name: {bad}", missing_message

    # The control still works.
    still = cd.get_deployment_group(
        applicationName=app, deploymentGroupName=ok_filters
    )["deploymentGroupInfo"]
    assert still.get("ec2TagFilters") == [TAG_FILTER], (
        f"the control group was disturbed by the refused call: {still!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)


# _error raises on an unexpected success.

def _error(fn):
    """(code, message) of the raised ClientError. An unexpected SUCCESS raises, because a
    target accepting a call real AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _dg_names(cd, app):
    """Every deployment group under the application, paginated, as a set."""
    names = set()
    token = None
    while True:
        kwargs = {"applicationName": app}
        if token:
            kwargs["nextToken"] = token
        page = cd.list_deployment_groups(**kwargs)
        names.update(page.get("deploymentGroups") or [])
        token = page.get("nextToken")
        if not token:
            return names


def _create_application(ctx, compute_platform="Server"):
    cd = ctx.client("codedeploy")
    name = ctx.unique_name("sim2real-behav-cd-app-")
    cd.create_application(applicationName=name, computePlatform=compute_platform)
    ctx.on_cleanup(lambda: cd.delete_application(applicationName=name))
    return name


def _create_service_role(ctx):
    cached = getattr(ctx, "_cd_service_role_arn", None)
    if cached:
        return cached
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-role-codedeploy-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "codedeploy.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Path="/sim2real/",
        Tags=[
            {"Key": "sim2real:managed", "Value": "true"},
            {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
        ],
    )

    def _del_role():
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            try:
                iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_del_role)
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="codedeploy-inline",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
        }),
    )
    # No sleep here: IAM-role-assumability propagation delay is absorbed by
    # _create_dg_control's bounded retry on InvalidRoleException below.
    arn = resp["Role"]["Arn"]
    ctx._cd_service_role_arn = arn
    return arn


def _create_dg_control(ctx, app, *, deployment_config="CodeDeployDefault.OneAtATime",
                       name=None, **extra):
    """Create a control deployment group. Provisions no compute: without
    autoScalingGroups / ecsServices there is no fleet to launch."""
    cd = ctx.client("codedeploy")
    name = name or ctx.unique_name("sim2real-behav-cd-dg-")
    kwargs = {
        "applicationName": app,
        "deploymentGroupName": name,
        "deploymentConfigName": deployment_config,
        "serviceRoleArn": _create_service_role(ctx),
    }
    kwargs.update(extra)
    # A freshly minted service role is not immediately assumable by CodeDeploy; poll
    # through that window ONLY, so a genuinely bad config still fails fast.
    deadline = time.monotonic() + 75
    while True:
        try:
            cd.create_deployment_group(**kwargs)
            break
        except ClientError as exc:
            err = exc.response.get("Error", {})
            msg = (err.get("Message") or "").lower()
            transient = err.get("Code") == "InvalidRoleException" and (
                "assume" in msg or "not authorized" in msg or "permissions required" in msg
            )
            if transient and time.monotonic() < deadline:
                time.sleep(3)
                continue
            raise
    ctx.on_cleanup(
        lambda: cd.delete_deployment_group(applicationName=app, deploymentGroupName=name)
    )
    return name
