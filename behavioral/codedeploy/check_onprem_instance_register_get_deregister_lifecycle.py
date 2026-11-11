"""onprem-instance-register-get-deregister-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "onprem-instance-register-get-deregister-lifecycle"
GROUP = "state-machine"
SERVICES = ["codedeploy"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A registered on-premises instance is visible via Get and the Registered list;
    deregistering removes it entirely: Get fails with InstanceNotRegisteredException and it
    drops out of the Registered list."""
    codedeploy = ctx.client("codedeploy")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    instance_name = ctx.unique_name("sim2real-cd-onprem-")
    user_arn = f"arn:aws:iam::{account_id}:user/{ctx.unique_name('sim2real-cd-onprem-user-')}"

    codedeploy.register_on_premises_instance(instanceName=instance_name, iamUserArn=user_arn)
    ctx.on_cleanup(lambda: _safe_deregister(codedeploy, instance_name))

    info = codedeploy.get_on_premises_instance(instanceName=instance_name)["instanceInfo"]
    assert info["instanceName"] == instance_name, (
        f"expected instanceName {instance_name!r}, got {info['instanceName']!r}"
    )
    assert info["iamUserArn"] == user_arn, (
        f"expected iamUserArn {user_arn!r}, got {info['iamUserArn']!r}"
    )
    assert "deregisterTime" not in info, (
        f"expected no deregisterTime before deregistration, got {info.get('deregisterTime')!r}"
    )

    registered_names = codedeploy.list_on_premises_instances(registrationStatus="Registered")[
        "instanceNames"
    ]
    assert instance_name in registered_names, (
        f"expected {instance_name!r} in Registered list, got {registered_names!r}"
    )

    codedeploy.deregister_on_premises_instance(instanceName=instance_name)

    try:
        codedeploy.get_on_premises_instance(instanceName=instance_name)
        raise AssertionError(
            "expected GetOnPremisesInstance to fail with InstanceNotRegisteredException "
            "after deregistration, but it returned successfully"
        )
    except ClientError as e:
        assert e.response["Error"]["Code"] == "InstanceNotRegisteredException", (
            f"expected InstanceNotRegisteredException, got {e.response['Error']['Code']}"
        )
        message = e.response["Error"].get("Message")
        assert message == f"The requested host does not exist. Host: {instance_name}", message

    registered_after = codedeploy.list_on_premises_instances(registrationStatus="Registered")[
        "instanceNames"
    ]
    assert instance_name not in registered_after, (
        f"expected {instance_name!r} to drop out of Registered list after deregistration, "
        f"got {registered_after!r}"
    )


# ===== helpers =====


def _safe_deregister(codedeploy, instance_name):
    try:
        codedeploy.deregister_on_premises_instance(instanceName=instance_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InstanceNotRegisteredException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
