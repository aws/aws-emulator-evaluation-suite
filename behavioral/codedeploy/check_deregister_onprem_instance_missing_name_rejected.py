"""deregister-onprem-instance-missing-name-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deregister-onprem-instance-missing-name-rejected"
GROUP = "error-semantics"
SERVICES = ["codedeploy"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeregisterOnPremisesInstance with an empty-string instanceName raises
    InstanceNameRequiredException, while deregistering a real registered instance still
    succeeds and observably flips its registration state."""
    cd = ctx.client("codedeploy")

    # an empty string is a *present* value (unlike an omitted key), so it clears botocore's
    # local "required parameter" client-side validation and reaches the service, which
    # rejects it with the documented, service-side InstanceNameRequiredException.
    code, message = _error(lambda: cd.deregister_on_premises_instance(instanceName=""))
    assert code == "InstanceNameRequiredException", f"expected InstanceNameRequiredException, got {code!r}"
    assert message == "Instance name is missing", message

    # positive control: deregistering a real, registered instance succeeds, and CodeDeploy
    # removes the instance's record entirely -- a subsequent GetOnPremisesInstance for the same
    # name raises InstanceNotRegisteredException (empirically verified against real AWS; the
    # instance is not kept around in a "deregistered" state with a visible deregisterTime).
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    arn = f"arn:aws:iam::{account_id}:user/{ctx.unique_name('sim2real-cd-user-')}"
    name = ctx.unique_name("sim2real-cd-onprem-deregme-")
    cd.register_on_premises_instance(instanceName=name, iamUserArn=arn)
    ctx.on_cleanup(lambda: _safe_deregister(cd, name))

    before = _poll_get_instance(cd, name, timeout_s=90.0)
    assert "deregisterTime" not in before, f"expected no deregisterTime before deregistration, got {before!r}"

    cd.deregister_on_premises_instance(instanceName=name)

    _poll_until(
        lambda: _get_instance_or_none(cd, name), lambda info: info is None, timeout_s=90.0
    )
    after_code, after_message = _error(lambda: cd.get_on_premises_instance(instanceName=name))
    assert after_code == "InstanceNotRegisteredException", (
        f"expected InstanceNotRegisteredException after deregistration, got {after_code!r}"
    )
    assert after_message == f"The requested host does not exist. Host: {name}", after_message

    # empirically verified against real AWS: unlike GetOnPremisesInstance, a repeat
    # DeregisterOnPremisesInstance on the same (now-gone) instance is a no-op success, not a
    # not-found error.
    cd.deregister_on_premises_instance(instanceName=name)



# ===== helpers =====

def _error(fn):
    """Call fn(); return (code, message) of its botocore error. An unexpected SUCCESS raises,
    because a target ACCEPTING input real AWS refuses is the strongest signal available and
    must not be reported as an error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected rejection but call succeeded with {result!r}")


def _safe_deregister(cd, name):
    try:
        cd.deregister_on_premises_instance(instanceName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InstanceNotRegisteredException":
            raise


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0):
    import time

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last observed value: {last!r}")


def _get_instance_or_none(cd, name):
    """GetOnPremisesInstance, but a transient 'not registered' response (registration/
    deregistration still propagating) is treated as 'not there yet' rather than a hard error."""
    try:
        return cd.get_on_premises_instance(instanceName=name)["instanceInfo"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "InstanceNotRegisteredException":
            return None
        raise


def _poll_get_instance(cd, name, timeout_s=60.0):
    return _poll_until(
        lambda: _get_instance_or_none(cd, name), lambda info: info is not None, timeout_s=timeout_s
    )



if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
