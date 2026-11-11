"""create-deployment-group-conflicting-tag-filters-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-deployment-group-conflicting-tag-filters-rejected"
GROUP = "overly-permissive"
SERVICES = ["codedeploy"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDeploymentGroup with both onPremisesInstanceTagFilters and onPremisesTagSet raises
    InvalidOnPremisesTagCombinationException and creates no group, while one selector alone creates."""
    cd = ctx.client("codedeploy")
    role_arn = _create_service_role(ctx)
    app = ctx.unique_name("sim2real-cd-app-")
    cd.create_application(applicationName=app, computePlatform="Server")
    ctx.on_cleanup(lambda: cd.delete_application(applicationName=app))

    tag_filter = [{"Key": ctx.unique_name("sim2real-tag-"), "Value": "x", "Type": "KEY_AND_VALUE"}]
    tag_set = {"onPremisesTagSetList": [tag_filter]}

    # Positive control first: this warms up (and proves) IAM role propagation via the
    # existing InvalidRoleException retry loop, so the negative assertion below isn't
    # confounded by a fresh role's eventual-consistency window.
    good_group = ctx.unique_name("sim2real-cd-dg-ok-")
    _create_deployment_group(ctx, cd, app, good_group, role_arn, onPremisesInstanceTagFilters=tag_filter)
    got = cd.get_deployment_group(applicationName=app, deploymentGroupName=good_group)["deploymentGroupInfo"]
    assert got["onPremisesInstanceTagFilters"] == tag_filter, got["onPremisesInstanceTagFilters"]

    conflicting_group = ctx.unique_name("sim2real-cd-dg-conflict-")
    deadline = time.monotonic() + 30
    while True:
        code, message = _error(lambda: cd.create_deployment_group(
            applicationName=app,
            deploymentGroupName=conflicting_group,
            serviceRoleArn=role_arn,
            onPremisesInstanceTagFilters=tag_filter,
            onPremisesTagSet=tag_set,
        ))
        if code != "InvalidRoleException" or time.monotonic() > deadline:
            break
        time.sleep(2)
    assert code == "InvalidOnPremisesTagCombinationException", code
    assert message == (
        "The request specified both OnPremisesTagFilters and OnPremisesTagSet, but only one "
        "of these data types can be used in a single call. Remove one tag specification "
        "type, and then try again."
    ), message

    # The rejected group must not have been created.
    not_found_code, not_found_message = _error(lambda: cd.get_deployment_group(
        applicationName=app, deploymentGroupName=conflicting_group
    ))
    assert not_found_code == "DeploymentGroupDoesNotExistException", not_found_code
    assert not_found_message == f"No Deployment Group found for name: {conflicting_group}", not_found_message


def _error(fn):
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises, because an
    over-permissive target accepting a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_service_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cd-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "codedeploy.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSCodeDeployRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    return role_arn


def _create_deployment_group(ctx, cd, application_name, deployment_group_name, service_role_arn, **kwargs):
    deadline = time.monotonic() + 30
    while True:
        try:
            resp = cd.create_deployment_group(
                applicationName=application_name,
                deploymentGroupName=deployment_group_name,
                serviceRoleArn=service_role_arn,
                **kwargs,
            )
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidRoleException" or time.monotonic() > deadline:
                raise
            time.sleep(2)
    ctx.on_cleanup(lambda: cd.delete_deployment_group(
        applicationName=application_name, deploymentGroupName=deployment_group_name
    ))
    return resp


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
