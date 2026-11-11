"""register-onprem-instance-duplicate-iam-user-arn-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "register-onprem-instance-duplicate-iam-user-arn-rejected"
GROUP = "error-semantics"
SERVICES = ["codedeploy"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Registering a second on-premises instance with a bound IAM user ARN fails with
    IamUserArnAlreadyRegisteredException, leaves it unregistered and the first binding intact; a distinct ARN
    registers fine, and after the first instance is deregistered the same ARN registers again.
    """
    cd = ctx.client("codedeploy")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    shared_arn = f"arn:aws:iam::{account_id}:user/{ctx.unique_name('sim2real-cd-user-')}"
    instance_a = ctx.unique_name("sim2real-cd-onprem-a-")
    cd.register_on_premises_instance(instanceName=instance_a, iamUserArn=shared_arn)
    ctx.on_cleanup(lambda: _deregister_if_present(cd, instance_a))

    # positive control: instance_a's own binding round-trips at an independent read
    info_a = cd.get_on_premises_instance(instanceName=instance_a)["instanceInfo"]
    assert info_a.get("iamUserArn") == shared_arn, (
        f"instance_a must round-trip {shared_arn!r}, got {info_a.get('iamUserArn')!r}"
    )

    instance_b = ctx.unique_name("sim2real-cd-onprem-b-")
    error = _client_error(
        lambda: cd.register_on_premises_instance(instanceName=instance_b, iamUserArn=shared_arn)
    )
    assert error == (
        "IamUserArnAlreadyRegisteredException",
        "The on-premises instance could not be registered because the request included an IAM "
        "user ARN that has already been used to register an instance. Include either a different "
        "IAM user ARN or IAM session ARN in the request, and then try again.",
    ), f"reusing a bound iamUserArn must raise IamUserArnAlreadyRegisteredException, got {error!r}"

    # effect absent: instance_b was never actually registered
    error_b = _client_error(lambda: cd.get_on_premises_instance(instanceName=instance_b))
    assert error_b == (
        "InstanceNotRegisteredException",
        f"The requested host does not exist. Host: {instance_b}",
    ), f"the refused instance_b must not exist, GetOnPremisesInstance answered {error_b!r}"

    # the refused registration must not have disturbed instance_a's own binding
    still_a = cd.get_on_premises_instance(instanceName=instance_a)["instanceInfo"]
    assert still_a.get("iamUserArn") == shared_arn, (
        f"the refused registration must not rebind instance_a's ARN: {still_a.get('iamUserArn')!r}"
    )

    # positive control: a different ARN registers a different instance successfully
    other_arn = f"arn:aws:iam::{account_id}:user/{ctx.unique_name('sim2real-cd-user2-')}"
    instance_c = ctx.unique_name("sim2real-cd-onprem-c-")
    cd.register_on_premises_instance(instanceName=instance_c, iamUserArn=other_arn)
    ctx.on_cleanup(lambda: _deregister_if_present(cd, instance_c))
    info_c = cd.get_on_premises_instance(instanceName=instance_c)["instanceInfo"]
    assert info_c["iamUserArn"] == other_arn

    # restore: releasing instance_a's binding frees shared_arn, and the identical call
    # that was refused above succeeds
    cd.deregister_on_premises_instance(instanceName=instance_a)
    _wait_deregistered(cd, instance_a)
    cd.register_on_premises_instance(instanceName=instance_b, iamUserArn=shared_arn)
    ctx.on_cleanup(lambda: _deregister_if_present(cd, instance_b))
    info_b = cd.get_on_premises_instance(instanceName=instance_b)["instanceInfo"]
    assert info_b.get("iamUserArn") == shared_arn, (
        f"after releasing the binding, instance_b must register with {shared_arn!r}, "
        f"got {info_b.get('iamUserArn')!r}"
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


def _deregister_if_present(cd, name):
    try:
        cd.deregister_on_premises_instance(instanceName=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "InstanceNotRegisteredException":
            raise


def _wait_deregistered(cd, name, timeout_s=60):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            info = cd.get_on_premises_instance(instanceName=name)["instanceInfo"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "InstanceNotRegisteredException":
                return
            raise
        if info.get("deregisterTime") is not None:
            return
        time.sleep(2)
    raise AssertionError(
        f"{name} never reached a deregistered state within {timeout_s}s; it would remain "
        "registered in the account"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
