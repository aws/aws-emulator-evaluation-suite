"""add-tags-onprem-instance-not-registered-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "add-tags-onprem-instance-not-registered-rejected"
GROUP = "error-semantics"
SERVICES = ["codedeploy"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AddTagsToOnPremisesInstances targeting an unregistered instance name raises
    InstanceNotRegisteredException and does not implicitly create it; tagging a genuinely
    registered instance succeeds and the tag is actually applied."""
    cd = ctx.client("codedeploy")
    iam = ctx.client("iam")

    missing_name = ctx.unique_name("sim2real-onprem-missing-")
    code, message = _error(
        lambda: cd.add_tags_to_on_premises_instances(
            instanceNames=[missing_name], tags=[{"Key": "sim2real-tag", "Value": "v1"}]
        )
    )
    assert code == "InstanceNotRegisteredException", (
        f"AddTagsToOnPremisesInstances on never-registered {missing_name!r} returned error "
        f"code {code!r}, expected 'InstanceNotRegisteredException'"
    )
    expected = f"Host {missing_name} is not registered"
    assert message == expected, f"AddTagsToOnPremisesInstances message {message!r}, expected {expected!r}"

    # effect absent: still not registered afterwards (the call did not implicitly create it)
    get_code, get_message = _error(lambda: cd.get_on_premises_instance(instanceName=missing_name))
    assert get_code == "InstanceNotRegisteredException", (
        f"after the rejected AddTagsToOnPremisesInstances, GetOnPremisesInstance on "
        f"{missing_name!r} returned error code {get_code!r}, expected the instance to still "
        f"be unregistered ('InstanceNotRegisteredException')"
    )
    expected_get = f"The requested host does not exist. Host: {missing_name}"
    assert get_message == expected_get, (
        f"GetOnPremisesInstance message {get_message!r}, expected {expected_get!r}"
    )

    # positive control: tagging a real registered instance succeeds and the tag is applied
    user_name = ctx.unique_name("sim2real-onprem-user-")
    user_arn = iam.create_user(UserName=user_name)["User"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))

    real_name = ctx.unique_name("sim2real-onprem-real-")
    cd.register_on_premises_instance(instanceName=real_name, iamUserArn=user_arn)
    ctx.on_cleanup(lambda: cd.deregister_on_premises_instance(instanceName=real_name))

    cd.add_tags_to_on_premises_instances(
        instanceNames=[real_name], tags=[{"Key": "sim2real-tag", "Value": "v1"}]
    )
    info = cd.get_on_premises_instance(instanceName=real_name)["instanceInfo"]
    assert {"Key": "sim2real-tag", "Value": "v1"} in info["tags"], (
        f"a registered instance's tags after AddTagsToOnPremisesInstances were "
        f"{info['tags']!r}, expected to contain {{'Key': 'sim2real-tag', 'Value': 'v1'}}"
    )


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(
        f"expected a ClientError (InstanceNotRegisteredException) but the call SUCCEEDED and "
        f"returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
