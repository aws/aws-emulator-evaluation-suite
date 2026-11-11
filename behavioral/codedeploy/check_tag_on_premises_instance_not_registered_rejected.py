"""tag-on-premises-instance-not-registered-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-on-premises-instance-not-registered-rejected"
GROUP = "overly-permissive"
SERVICES = ["codedeploy"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AddTagsToOnPremisesInstances targeting an instance name that was never
    registered must fail with InstanceNotRegisteredException rather than silently
    accepting tags for a nonexistent target."""
    cd = ctx.client("codedeploy")
    iam = ctx.client("iam")

    never_registered = ctx.unique_name("sim2real-cd-tag-ghost-")
    tag = {"Key": "sim2real-owner", "Value": "behavioral-check"}

    error = _client_error(
        lambda: cd.add_tags_to_on_premises_instances(tags=[tag], instanceNames=[never_registered])
    )
    assert error == (
        "InstanceNotRegisteredException",
        f"Host {never_registered} is not registered",
    ), f"expected InstanceNotRegisteredException tagging an unregistered instance, got {error!r}"

    # effect absent: the tag was not associated with anything (the instance still
    # cannot be resolved at all)
    absent = _client_error(lambda: cd.get_on_premises_instance(instanceName=never_registered))
    assert absent == (
        "InstanceNotRegisteredException",
        f"The requested host does not exist. Host: {never_registered}",
    ), (
        f"expected InstanceNotRegisteredException reading back the never-registered "
        f"instance, got {absent!r}"
    )

    # positive control: tagging a real, registered on-premises instance succeeds
    user_name = ctx.unique_name("sim2real-cd-tag-user-")
    user_arn = iam.create_user(UserName=user_name)["User"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))

    real_name = ctx.unique_name("sim2real-cd-tag-real-")
    cd.register_on_premises_instance(instanceName=real_name, iamUserArn=user_arn)
    ctx.on_cleanup(lambda: cd.deregister_on_premises_instance(instanceName=real_name))

    cd.add_tags_to_on_premises_instances(tags=[tag], instanceNames=[real_name])
    info = cd.get_on_premises_instance(instanceName=real_name)["instanceInfo"]
    assert {"Key": "sim2real-owner", "Value": "behavioral-check"} in info["tags"], (
        f"expected the applied tag on the registered instance, got tags={info.get('tags')!r}"
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
