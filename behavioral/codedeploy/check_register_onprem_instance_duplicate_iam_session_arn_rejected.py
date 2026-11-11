"""register-onprem-instance-duplicate-iam-session-arn-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "register-onprem-instance-duplicate-iam-session-arn-rejected"
GROUP = "error-semantics"
SERVICES = ["codedeploy"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Registering a second on-premises instance with a bound IAM session ARN fails with
    IamSessionArnAlreadyRegisteredException and leaves it unregistered; an unused ARN registers fine, and
    after the first instance is deregistered the same ARN registers again.
    """
    cd = ctx.client("codedeploy")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    session_arn = (
        f"arn:aws:sts::{account_id}:assumed-role/sim2real-cd-role/{ctx.unique_name('sess-')}"
    )
    instance_a = ctx.unique_name("sim2real-onprem-a-")
    cd.register_on_premises_instance(instanceName=instance_a, iamSessionArn=session_arn)
    ctx.on_cleanup(lambda: _safe_deregister(cd, instance_a))
    info_a = cd.get_on_premises_instance(instanceName=instance_a)["instanceInfo"]
    assert info_a.get("iamSessionArn") == session_arn, (
        f"iamSessionArn must round-trip verbatim, got {info_a.get('iamSessionArn')!r}"
    )

    instance_b = ctx.unique_name("sim2real-onprem-b-")
    error = _client_error(
        lambda: cd.register_on_premises_instance(instanceName=instance_b, iamSessionArn=session_arn)
    )
    assert error == (
        "IamSessionArnAlreadyRegisteredException",
        "The on-premises instance could not be registered because the request included an IAM "
        "session ARN that has already been used to register a different instance. Include either "
        "a different IAM session ARN or IAM user ARN in the request, and then try again.",
    ), (
        f"reusing an already-registered iamSessionArn must raise "
        f"IamSessionArnAlreadyRegisteredException, got {error!r}"
    )

    # effect absent: instance_b was never registered
    get_error = _client_error(lambda: cd.get_on_premises_instance(instanceName=instance_b))
    assert get_error == (
        "InstanceNotRegisteredException",
        f"The requested host does not exist. Host: {instance_b}",
    ), (
        f"the refused instance {instance_b} must not exist; GetOnPremisesInstance answered "
        f"{get_error!r}"
    )

    # positive control: a different, unused IAM session ARN registers a new instance fine
    session_arn2 = (
        f"arn:aws:sts::{account_id}:assumed-role/sim2real-cd-role/{ctx.unique_name('sess2-')}"
    )
    instance_c = ctx.unique_name("sim2real-onprem-c-")
    cd.register_on_premises_instance(instanceName=instance_c, iamSessionArn=session_arn2)
    ctx.on_cleanup(lambda: _safe_deregister(cd, instance_c))
    info_c = cd.get_on_premises_instance(instanceName=instance_c)["instanceInfo"]
    assert info_c["instanceName"] == instance_c, info_c

    # restore: releasing the original binding by deregistering instance_a makes the
    # identical session ARN registrable again -- the constraint is on live registrations,
    # not retained after deregistration.
    cd.deregister_on_premises_instance(instanceName=instance_a)
    cd.register_on_premises_instance(instanceName=instance_b, iamSessionArn=session_arn)
    ctx.on_cleanup(lambda: _safe_deregister(cd, instance_b))
    info_b = cd.get_on_premises_instance(instanceName=instance_b)["instanceInfo"]
    assert info_b.get("iamSessionArn") == session_arn, (
        f"reused iamSessionArn must round-trip verbatim, got {info_b.get('iamSessionArn')!r}"
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


def _safe_deregister(cd, instance_name):
    try:
        cd.deregister_on_premises_instance(instanceName=instance_name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "InstanceNotRegisteredException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
