"""onprem-instance-duplicate-name-registration-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "onprem-instance-duplicate-name-registration-rejected"
GROUP = "state-machine"
SERVICES = ["codedeploy"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Re-registering a registered on-premises instance name fails with InstanceNameAlreadyRegisteredException
    and keeps the original IAM user binding, a distinct name registers fine, and after deregistration the name
    registers again bound to a new user.
    """
    cd = ctx.client("codedeploy")
    iam = ctx.client("iam")

    user1_name = ctx.unique_name("sim2real-cdonprem-user1-")
    user1_arn = iam.create_user(UserName=user1_name)["User"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user1_name))

    instance_name = ctx.unique_name("sim2real-onprem-dup-")
    cd.register_on_premises_instance(instanceName=instance_name, iamUserArn=user1_arn)
    ctx.on_cleanup(lambda: cd.deregister_on_premises_instance(instanceName=instance_name))

    user2_name = ctx.unique_name("sim2real-cdonprem-user2-")
    user2_arn = iam.create_user(UserName=user2_name)["User"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user2_name))

    code, message = _error(
        lambda: cd.register_on_premises_instance(instanceName=instance_name, iamUserArn=user2_arn)
    )
    assert code == "InstanceNameAlreadyRegisteredException", (
        f"re-registering a live instance name must raise InstanceNameAlreadyRegisteredException, "
        f"got {code!r}"
    )
    assert message == "Host name has already been registered or recently deregistered", message

    # Effect absent: the original registration's IAM ARN binding is unchanged.
    info = cd.get_on_premises_instance(instanceName=instance_name)["instanceInfo"]
    assert info["iamUserArn"] == user1_arn, (
        f"a refused re-registration must not rebind the ARN, got {info['iamUserArn']!r} "
        f"instead of {user1_arn!r}"
    )

    # Positive control: registering a distinctly-named instance with the second user
    # (which was rejected only because of the name collision above) succeeds.
    instance_name2 = ctx.unique_name("sim2real-onprem-ctrl-")
    cd.register_on_premises_instance(instanceName=instance_name2, iamUserArn=user2_arn)
    ctx.on_cleanup(lambda: cd.deregister_on_premises_instance(instanceName=instance_name2))
    info2 = cd.get_on_premises_instance(instanceName=instance_name2)["instanceInfo"]
    assert info2["iamUserArn"] == user2_arn, (
        f"a distinctly-named registration must succeed and bind the requested ARN, got "
        f"{info2['iamUserArn']!r} instead of {user2_arn!r}"
    )

    # Restore: deregistering the original frees the name. The identical call that was
    # just rejected succeeds against the same name. A fresh third user's ARN is
    # used here, not user2_arn: that ARN is bound to instance_name2 above, and reusing it
    # raises IamUserArnAlreadyRegisteredException, a different rejection.
    cd.deregister_on_premises_instance(instanceName=instance_name)
    freed_code, freed_message = _error(lambda: cd.get_on_premises_instance(instanceName=instance_name))
    assert freed_code == "InstanceNotRegisteredException", (
        f"after deregistering, an independent read must report InstanceNotRegisteredException, "
        f"got {freed_code!r}"
    )
    assert freed_message == f"The requested host does not exist. Host: {instance_name}", (
        freed_message
    )

    user3_name = ctx.unique_name("sim2real-cdonprem-user3-")
    user3_arn = iam.create_user(UserName=user3_name)["User"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user3_name))

    cd.register_on_premises_instance(instanceName=instance_name, iamUserArn=user3_arn)
    restored_info = cd.get_on_premises_instance(instanceName=instance_name)["instanceInfo"]
    assert restored_info["iamUserArn"] == user3_arn, (
        f"once freed, the name must be registrable by a new user, got "
        f"{restored_info['iamUserArn']!r} instead of {user3_arn!r}"
    )


def _error(fn):
    """(code, message) of the ClientError fn() raises. An unexpected SUCCESS raises, so a
    target that accepts what AWS refuses never reaches a code comparison."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
