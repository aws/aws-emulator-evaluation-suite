"""on-premises-instance-register-deregister-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "on-premises-instance-register-deregister-lifecycle"
GROUP = "state-machine"
SERVICES = ["codedeploy"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A registered on-premises instance is returned by GetOnPremisesInstance and ListOnPremisesInstances; after
    deregistration it leaves the list, and GetOnPremisesInstance and AddTagsToOnPremisesInstances both fail
    with InstanceNotRegisteredException and their exact messages.
    """
    cd = ctx.client("codedeploy")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    instance_name = ctx.unique_name("sim2real-cd-onprem-")
    iam_user_arn = f"arn:aws:iam::{account_id}:user/{ctx.unique_name('sim2real-cd-user-')}"

    cd.register_on_premises_instance(instanceName=instance_name, iamUserArn=iam_user_arn)
    still_registered = {"value": True}

    def _cleanup():
        if still_registered["value"]:
            cd.deregister_on_premises_instance(instanceName=instance_name)

    ctx.on_cleanup(_cleanup)

    info = cd.get_on_premises_instance(instanceName=instance_name)["instanceInfo"]
    assert info["instanceName"] == instance_name, (
        f"expected instanceName {instance_name!r}, got {info['instanceName']!r}"
    )
    assert info["iamUserArn"] == iam_user_arn, (
        f"expected iamUserArn {iam_user_arn!r}, got {info['iamUserArn']!r}"
    )
    assert info["instanceArn"], "expected a non-empty instanceArn on a freshly registered instance"

    def _registered_names():
        names = []
        paginator = cd.get_paginator("list_on_premises_instances")
        for page in paginator.paginate(registrationStatus="Registered"):
            names.extend(page["instanceNames"])
        return names

    names_before = _registered_names()
    assert instance_name in names_before, (
        f"expected {instance_name!r} in the Registered list, got {names_before!r}"
    )

    cd.deregister_on_premises_instance(instanceName=instance_name)
    still_registered["value"] = False

    names_after = _registered_names()
    assert instance_name not in names_after, (
        f"expected {instance_name!r} to drop out of the Registered list after deregistration, "
        f"still present: {names_after!r}"
    )

    code, message = _error(lambda: cd.get_on_premises_instance(instanceName=instance_name))
    assert code == "InstanceNotRegisteredException", (
        f"expected GetOnPremisesInstance on a deregistered instance to fail with "
        f"InstanceNotRegisteredException, got {code!r}"
    )
    assert message == f"The requested host does not exist. Host: {instance_name}", message

    # DeregisterOnPremisesInstance is idempotent: a second call on the same dead name
    # must not raise. This is measured, not assumed -- see the docstring.
    cd.deregister_on_premises_instance(instanceName=instance_name)

    tag_code, tag_message = _error(
        lambda: cd.add_tags_to_on_premises_instances(
            instanceNames=[instance_name], tags=[{"Key": "sim2real-tag", "Value": "v1"}]
        )
    )
    assert tag_code == "InstanceNotRegisteredException", (
        f"expected AddTagsToOnPremisesInstances on the deregistered {instance_name!r} to fail "
        f"with InstanceNotRegisteredException, got {tag_code!r}"
    )
    assert tag_message == f"Host {instance_name} is not registered", tag_message


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
