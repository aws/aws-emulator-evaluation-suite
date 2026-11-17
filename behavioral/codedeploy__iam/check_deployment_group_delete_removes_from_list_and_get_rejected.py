"""deployment-group-delete-removes-from-list-and-get-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deployment-group-delete-removes-from-list-and-get-rejected"
GROUP = "overly-permissive"
SERVICES = ["codedeploy", "iam"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteDeploymentGroup on a Lambda BLUE_GREEN deployment group removes it from
    ListDeploymentGroups and makes GetDeploymentGroup raise DeploymentGroupDoesNotExistException
    naming it, while a sibling deployment group under the same application is unaffected."""
    cd = ctx.client("codedeploy")

    app = ctx.unique_name("sim2real-behav-cdapp-")
    cd.create_application(applicationName=app, computePlatform="Lambda")
    ctx.on_cleanup(lambda: cd.delete_application(applicationName=app))

    role = _create_service_role(ctx)
    style = {"deploymentType": "BLUE_GREEN", "deploymentOption": "WITH_TRAFFIC_CONTROL"}

    target = ctx.unique_name("sim2real-behav-cddg-target-")
    _create_deployment_group_with_retry(
        cd, applicationName=app, deploymentGroupName=target,
        serviceRoleArn=role, deploymentStyle=style,
    )
    ctx.on_cleanup(lambda: cd.delete_deployment_group(applicationName=app, deploymentGroupName=target))

    sibling = ctx.unique_name("sim2real-behav-cddg-sibling-")
    _create_deployment_group_with_retry(
        cd, applicationName=app, deploymentGroupName=sibling,
        serviceRoleArn=role, deploymentStyle=style,
    )
    ctx.on_cleanup(lambda: cd.delete_deployment_group(applicationName=app, deploymentGroupName=sibling))

    before = set(cd.list_deployment_groups(applicationName=app)["deploymentGroups"])
    assert before == {target, sibling}, before

    cd.delete_deployment_group(applicationName=app, deploymentGroupName=target)

    after = set(cd.list_deployment_groups(applicationName=app)["deploymentGroups"])
    assert after == {sibling}, (
        f"ListDeploymentGroups must drop exactly the deleted group and keep its sibling: "
        f"{after!r}"
    )

    code, message = _error(
        lambda: cd.get_deployment_group(applicationName=app, deploymentGroupName=target)
    )
    assert code == "DeploymentGroupDoesNotExistException", code
    assert message == f"No Deployment Group found for name: {target}", message

    still = cd.get_deployment_group(
        applicationName=app, deploymentGroupName=sibling
    )["deploymentGroupInfo"]
    assert still["deploymentGroupName"] == sibling, (
        f"the sibling group must still read back after the target's delete: {still!r}"
    )


def _error(fn):
    """(code, message) of the raised ClientError. An unexpected SUCCESS raises, because a
    target accepting a call real AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _create_service_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-cdrole-")
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
    return resp["Role"]["Arn"]


def _create_deployment_group_with_retry(cd, **kwargs):
    # A freshly-minted service role is not immediately assumable by CodeDeploy until the
    # trust relationship propagates; retry the create through that window, but only for the
    # assume-role transient so a genuinely bad config still fails fast.
    deadline = time.monotonic() + 75
    while True:
        try:
            cd.create_deployment_group(**kwargs)
            return
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
