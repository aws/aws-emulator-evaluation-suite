"""deregister-onprem-instance-invalid-name-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deregister-onprem-instance-invalid-name-rejected"
GROUP = "error-semantics"
SERVICES = ["codedeploy"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeregisterOnPremisesInstance with a syntactically invalid instance name raises
    InvalidInstanceNameException and leaves an existing registered instance untouched; a valid
    deregistration of that real instance still succeeds."""
    cd = ctx.client("codedeploy")
    iam = ctx.client("iam")

    user_name = ctx.unique_name("sim2real-onprem-user-")
    user_arn = iam.create_user(UserName=user_name)["User"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))

    real_name = ctx.unique_name("sim2real-onprem-")
    cd.register_on_premises_instance(instanceName=real_name, iamUserArn=user_arn)
    deregistered = {"done": False}

    def _cleanup_deregister():
        if not deregistered["done"]:
            try:
                cd.deregister_on_premises_instance(instanceName=real_name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "InstanceNotRegisteredException":
                    raise

    ctx.on_cleanup(_cleanup_deregister)

    # registration can lag briefly, so poll until the instance is observably present
    # before running the negative test against it
    info = _poll_get_instance(cd, real_name)
    assert "deregisterTime" not in info, f"newly-registered instance already has a deregisterTime: {info}"

    # instance names must match CodeDeploy's [A-Za-z0-9+=,.@_-] charset; spaces/bangs are invalid
    invalid_name = "bad name/with invalid chars !!"
    code, message = _error(lambda: cd.deregister_on_premises_instance(instanceName=invalid_name))
    assert code == "InvalidInstanceNameException", f"expected InvalidInstanceNameException, got {code!r}"
    assert message == "Instance name contains invalid characters.", message

    # effect absent: the real instance is untouched, still registered (no deregisterTime)
    info = cd.get_on_premises_instance(instanceName=real_name)["instanceInfo"]
    assert "deregisterTime" not in info, f"real instance was mutated by the rejected call: {info}"

    # positive control: deregistering the real instance with a valid name succeeds
    cd.deregister_on_premises_instance(instanceName=real_name)
    deregistered["done"] = True
    code_after, message_after = _error(lambda: cd.get_on_premises_instance(instanceName=real_name))
    assert code_after == "InstanceNotRegisteredException", (
        f"expected InstanceNotRegisteredException after deregistration, got {code_after!r}"
    )
    assert message_after == f"The requested host does not exist. Host: {real_name}", message_after


# ===== helpers =====
def _error(fn):
    """Call fn(); return the botocore (code, message). An unexpected SUCCESS raises, because
    reporting acceptance as a code mismatch hides an over-permissive target."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _poll_get_instance(cd, instance_name: str, timeout_s: float = 60.0) -> dict:
    deadline = time.monotonic() + timeout_s
    last_exc: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            return cd.get_on_premises_instance(instanceName=instance_name)["instanceInfo"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InstanceNotRegisteredException":
                raise
            last_exc = exc
            time.sleep(2)
    raise AssertionError(f"instance {instance_name} never became visible: {last_exc}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
