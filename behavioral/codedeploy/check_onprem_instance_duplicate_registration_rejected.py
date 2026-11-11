"""onprem-instance-duplicate-registration-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "onprem-instance-duplicate-registration-rejected"
GROUP = "state-machine"
SERVICES = ["codedeploy"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Re-registering a registered on-premises instance name fails with
    InstanceNameAlreadyRegisteredException and leaves the original iamUserArn untouched;
    deregistering the original frees the name, and a different name still registers."""
    codedeploy = ctx.client("codedeploy")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    instance_name = ctx.unique_name("sim2real-cd-dup-")
    original_arn = f"arn:aws:iam::{account_id}:user/{ctx.unique_name('sim2real-cd-user-a-')}"
    codedeploy.register_on_premises_instance(instanceName=instance_name, iamUserArn=original_arn)
    ctx.on_cleanup(lambda: _safe_deregister(codedeploy, instance_name))

    other_arn = f"arn:aws:iam::{account_id}:user/{ctx.unique_name('sim2real-cd-user-b-')}"
    code, message = _error(
        lambda: codedeploy.register_on_premises_instance(
            instanceName=instance_name, iamUserArn=other_arn
        )
    )
    assert code == "InstanceNameAlreadyRegisteredException", code
    assert message == "Host name has already been registered or recently deregistered", message

    # effect absent: the original registration's ARN must be unchanged by the rejected call
    info = codedeploy.get_on_premises_instance(instanceName=instance_name)["instanceInfo"]
    assert info["iamUserArn"] == original_arn, (
        f"expected unchanged iamUserArn={original_arn!r} after the rejected call, "
        f"got {info.get('iamUserArn')!r}"
    )

    # restore: the rejection is specific to the name being taken, not to the identical call
    # forever — deregistering the original and reissuing the identical call now succeeds.
    codedeploy.deregister_on_premises_instance(instanceName=instance_name)
    _retry_until_registered(codedeploy, instance_name, other_arn)
    restored_info = codedeploy.get_on_premises_instance(instanceName=instance_name)["instanceInfo"]
    assert restored_info["iamUserArn"] == other_arn, (
        f"expected the freed name to accept iamUserArn={other_arn!r} after restore, "
        f"got {restored_info.get('iamUserArn')!r}"
    )

    # positive control: a distinct instance name still registers fine in the same account
    control_name = ctx.unique_name("sim2real-cd-dup-ctrl-")
    control_arn = f"arn:aws:iam::{account_id}:user/{ctx.unique_name('sim2real-cd-user-c-')}"
    codedeploy.register_on_premises_instance(instanceName=control_name, iamUserArn=control_arn)
    ctx.on_cleanup(lambda: _safe_deregister(codedeploy, control_name))
    control_info = codedeploy.get_on_premises_instance(instanceName=control_name)["instanceInfo"]
    assert control_info["iamUserArn"] == control_arn, (
        f"expected control instance to bind iamUserArn={control_arn!r}, "
        f"got {control_info.get('iamUserArn')!r}"
    )


# ===== helpers =====


def _error(fn):
    """(code, message) of the ClientError fn() raises. An unexpected SUCCESS raises, so a
    target that accepts what AWS refuses never reaches a code comparison."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _retry_until_registered(codedeploy, instance_name, iam_user_arn):
    """Deregistration can trail the read path briefly; bounded retry for that window only."""
    deadline = time.monotonic() + 30
    last_code = None
    while time.monotonic() < deadline:
        try:
            codedeploy.register_on_premises_instance(
                instanceName=instance_name, iamUserArn=iam_user_arn
            )
            return
        except ClientError as e:
            last_code = e.response["Error"]["Code"]
            if last_code != "InstanceNameAlreadyRegisteredException":
                raise
            time.sleep(1)
    raise AssertionError(
        f"name {instance_name!r} still reported registered {last_code!r} 30s after deregister"
    )


def _safe_deregister(codedeploy, instance_name):
    try:
        codedeploy.deregister_on_premises_instance(instanceName=instance_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InstanceNotRegisteredException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
