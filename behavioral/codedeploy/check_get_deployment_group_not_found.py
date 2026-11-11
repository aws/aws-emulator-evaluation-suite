"""get-deployment-group-not-found."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-deployment-group-not-found"
GROUP = 'error-semantics'
SERVICES = ['codedeploy']

_MANAGED_TAGS = [{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-behav"}]


def _create_application(ctx, compute_platform="Server"):
    cd = ctx.client("codedeploy")
    name = ctx.unique_name("sim2real-behav-app-")
    cd.create_application(applicationName=name, computePlatform=compute_platform, tags=_MANAGED_TAGS)
    ctx.on_cleanup(lambda: cd.delete_application(applicationName=name))
    return name


def _create_service_role(ctx):
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
        Tags=_MANAGED_TAGS,
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


def _create_deployment_group(ctx, app, role_arn):
    """A real deployment group under `app`, used as the positive control: GetDeploymentGroup
    must succeed against it before the identical call on a never-created name is trusted to
    mean anything. Retries the create through the window where a freshly minted service role
    is not yet assumable by CodeDeploy (InvalidRoleException) -- a bounded wait, not a sleep."""
    cd = ctx.client("codedeploy")
    name = ctx.unique_name("sim2real-behav-dg-")
    deadline = time.monotonic() + 75
    while True:
        try:
            cd.create_deployment_group(
                applicationName=app,
                deploymentGroupName=name,
                deploymentConfigName="CodeDeployDefault.OneAtATime",
                serviceRoleArn=role_arn,
                tags=_MANAGED_TAGS,
            )
            break
        except ClientError as exc:
            err = exc.response.get("Error", {})
            code = err.get("Code")
            msg = (err.get("Message") or "").lower()
            transient_role = code == "InvalidRoleException" or ("assume" in msg or "not authorized" in msg)
            if transient_role and time.monotonic() < deadline:
                time.sleep(3)
                continue
            raise
    ctx.on_cleanup(lambda: cd.delete_deployment_group(applicationName=app, deploymentGroupName=name))
    return name


def _error(fn):
    """Call fn(); return (code, message) of its ClientError. An unexpected SUCCESS raises, because
    an emulator ACCEPTING a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Positive control: GetDeploymentGroup on a real deployment group under a real app
    succeeds and echoes its name. Negative: the identical call for a never-created group name
    under the SAME app -> DeploymentGroupDoesNotExistException."""
    cd = ctx.client("codedeploy")
    app = _create_application(ctx)
    role_arn = _create_service_role(ctx)
    real_dg = _create_deployment_group(ctx, app, role_arn)

    info = cd.get_deployment_group(applicationName=app, deploymentGroupName=real_dg)["deploymentGroupInfo"]
    assert info["deploymentGroupName"] == real_dg, info

    ghost = ctx.unique_name("sim2real-behav-" + "dg-ghost-")
    code, message = _error(
        lambda: cd.get_deployment_group(applicationName=app, deploymentGroupName=ghost)
    )
    assert code == "DeploymentGroupDoesNotExistException", code
    assert message == f"No Deployment Group found for name: {ghost}", message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
