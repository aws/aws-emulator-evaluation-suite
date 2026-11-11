"""register-on-premises-instance-missing-iam-arn-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "register-on-premises-instance-missing-iam-arn-rejected"
GROUP = "overly-permissive"
SERVICES = ["codedeploy"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RegisterOnPremisesInstance with neither iamUserArn nor iamSessionArn must fail
    with IamArnRequiredException, not default to an anonymous registration."""
    cd = ctx.client("codedeploy")
    anon_name = ctx.unique_name("sim2real-cd-onprem-anon-")

    error = _client_error(lambda: cd.register_on_premises_instance(instanceName=anon_name))
    assert error == (
        "IamArnRequiredException",
        "The on-premises instance could not be registered because no IAM ARN was included in "
        "the request. Include either an IAM session ARN or IAM user ARN in the request, and then "
        "try again.",
    ), f"expected IamArnRequiredException, got {error!r}"

    # the rejection must not have registered the instance under any status
    not_registered = _client_error(lambda: cd.get_on_premises_instance(instanceName=anon_name))
    assert not_registered == (
        "InstanceNotRegisteredException",
        f"The requested host does not exist. Host: {anon_name}",
    ), f"expected InstanceNotRegisteredException, got {not_registered!r}"
    names = cd.list_on_premises_instances()["instanceNames"]
    assert anon_name not in names, f"{anon_name!r} should not be registered, saw it in {names!r}"

    # positive control: registering with a real IAM user ARN succeeds
    iam = ctx.client("iam")
    user_name = ctx.unique_name("sim2real-cd-onprem-user-")
    user_arn = iam.create_user(
        UserName=user_name, Tags=[{"Key": "sim2real-check", "Value": CHECK}]
    )["User"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))

    real_name = ctx.unique_name("sim2real-cd-onprem-real-")
    cd.register_on_premises_instance(instanceName=real_name, iamUserArn=user_arn)
    ctx.on_cleanup(lambda: cd.deregister_on_premises_instance(instanceName=real_name))
    cd.add_tags_to_on_premises_instances(
        instanceNames=[real_name], tags=[{"Key": "sim2real-check", "Value": CHECK}]
    )

    info = cd.get_on_premises_instance(instanceName=real_name)["instanceInfo"]
    assert info["iamUserArn"] == user_arn, (
        f"expected iamUserArn {user_arn!r}, got {info.get('iamUserArn')!r}"
    )


def _client_error(fn):
    """Call fn(); return its botocore error as (code, message). An unexpected SUCCESS raises,
    because an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
