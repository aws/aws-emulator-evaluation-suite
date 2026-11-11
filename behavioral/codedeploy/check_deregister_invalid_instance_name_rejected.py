"""deregister-invalid-instance-name-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deregister-invalid-instance-name-rejected"
GROUP = "overly-permissive"
SERVICES = ["codedeploy"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeregisterOnPremisesInstance with a name in the reserved EC2-instance-ID format
    (i-xxxxxxxxxxxxxxxxx) must fail with InvalidInstanceNameException rather than
    succeeding as a no-op."""
    cd = ctx.client("codedeploy")
    iam = ctx.client("iam")

    # setup: a genuinely registered on-premises instance to use as the positive control
    user_name = ctx.unique_name("sim2real-cd-dereg-user-")
    user_arn = iam.create_user(UserName=user_name)["User"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))

    real_name = ctx.unique_name("sim2real-cd-dereg-real-")
    cd.register_on_premises_instance(instanceName=real_name, iamUserArn=user_arn)
    registered = True

    def _cleanup_real():
        if registered:
            try:
                cd.deregister_on_premises_instance(instanceName=real_name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "InstanceNotRegisteredException":
                    raise

    ctx.on_cleanup(_cleanup_real)

    # break exactly one thing: an instance name shaped like an EC2 instance ID is
    # reserved and rejected outright by DeregisterOnPremisesInstance
    bogus_name = "i-1234567890abcdef0"
    code, message = _error(lambda: cd.deregister_on_premises_instance(instanceName=bogus_name))
    assert code == "InvalidInstanceNameException", (
        f"expected InvalidInstanceNameException for EC2-instance-ID-shaped name, got {code!r}"
    )
    assert message == 'Host name cannot start with "i-"', message

    # effect absent: nothing was deregistered as a side effect of the rejected call
    # (the real instance still has no deregisterTime recorded). Registration can lag
    # briefly, so poll until the instance is observably present before asserting.
    still_registered = _poll_get_instance(cd, real_name)
    assert not still_registered.get("deregisterTime"), (
        f"real instance should be untouched by the rejected call, got "
        f"deregisterTime={still_registered.get('deregisterTime')!r}"
    )

    # positive control: deregistering the real instance succeeds and is observable
    # -- empirically, GetOnPremisesInstance stops recognizing the instance at all
    # once deregistered (it raises InstanceNotRegisteredException rather than
    # returning a record with a populated deregisterTime), so that transition is
    # the reliable observation point.
    cd.deregister_on_premises_instance(instanceName=real_name)
    registered = False
    deadline = time.monotonic() + 60.0
    seen = False
    while time.monotonic() < deadline:
        try:
            cd.get_on_premises_instance(instanceName=real_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "InstanceNotRegisteredException":
                seen = True
                break
            raise
        time.sleep(2)
    assert seen, "real instance was still recognized after DeregisterOnPremisesInstance"


# ===== helpers =====


def _error(fn):
    """Call fn(); return (code, message) of its botocore error. An unexpected SUCCESS raises,
    because a target ACCEPTING input real AWS refuses is the strongest signal available and
    must not be reported as an error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _list_all(cd, **kwargs) -> list[str]:
    names: list[str] = []
    token = None
    while True:
        params = dict(kwargs)
        if token:
            params["nextToken"] = token
        resp = cd.list_on_premises_instances(**params)
        names.extend(resp.get("instanceNames", []))
        token = resp.get("nextToken")
        if not token:
            break
    return names


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
