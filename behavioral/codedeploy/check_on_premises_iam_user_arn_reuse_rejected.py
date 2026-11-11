"""on-premises-iam-user-arn-reuse-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "on-premises-iam-user-arn-reuse-rejected"
GROUP = 'error-semantics'
SERVICES = ['codedeploy']


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Reusing an iamUserArn under a new on-premises instance name is refused with
    IamUserArnAlreadyRegisteredException and creates no record, while reusing the name with a
    fresh ARN raises the distinct InstanceNameAlreadyRegisteredException."""
    cd = ctx.client("codedeploy")

    name_a = ctx.unique_name("sim2real-behav-cd-onprem-a-")
    name_b = ctx.unique_name("sim2real-behav-cd-onprem-b-")
    name_c = ctx.unique_name("sim2real-behav-cd-onprem-c-")
    arn_shared = _iam_user_arn(ctx, name_a)
    arn_other = _iam_user_arn(ctx, name_c)

    # Control: A registers cleanly against the shared ARN.
    cd.register_on_premises_instance(instanceName=name_a, iamUserArn=arn_shared)
    _register_onprem_teardown(ctx, cd, name_a)
    info_a = cd.get_on_premises_instance(instanceName=name_a)["instanceInfo"]
    assert info_a.get("iamUserArn") == arn_shared, (
        f"iamUserArn must round-trip verbatim, got {info_a.get('iamUserArn')!r}"
    )
    registered = _list_onprem(cd, "Registered")
    assert name_a in registered, f"{name_a} must be listed as Registered"
    assert name_b not in registered, (
        f"precondition: {name_b} must not already exist"
    )

    # Break exactly one thing: a new instance name, the SAME iamUserArn.
    _register_onprem_teardown(ctx, cd, name_b)
    code, message = _error(
        lambda: cd.register_on_premises_instance(
            instanceName=name_b, iamUserArn=arn_shared
        )
    )
    assert code == "IamUserArnAlreadyRegisteredException", (
        f"reusing an already-registered iamUserArn must raise "
        f"IamUserArnAlreadyRegisteredException, got {code!r}; an emulator keyed only on "
        "instanceName accepts this and lets two hosts share one identity"
    )
    assert message == (
        "The on-premises instance could not be registered because the request included an IAM "
        "user ARN that has already been used to register an instance. Include either a "
        "different IAM user ARN or IAM session ARN in the request, and then try again."
    ), message

    # The effect is absent: no B record, and A is untouched.
    after = _list_onprem(cd, "Registered")
    assert name_b not in after, (
        f"a refused RegisterOnPremisesInstance must create no record, but {name_b} is "
        "listed as Registered"
    )
    missing, missing_message = _error(lambda: cd.get_on_premises_instance(instanceName=name_b))
    assert missing == "InstanceNotRegisteredException", (
        f"the refused instance {name_b} must not exist; GetOnPremisesInstance answered "
        f"{missing!r}"
    )
    assert missing_message == f"The requested host does not exist. Host: {name_b}", (
        missing_message
    )
    still_a = cd.get_on_premises_instance(instanceName=name_a)["instanceInfo"]
    assert still_a.get("iamUserArn") == arn_shared, (
        f"the refused registration must not rebind A's ARN: "
        f"{still_a.get('iamUserArn')!r}"
    )
    assert still_a.get("deregisterTime") is None, (
        f"the refused registration must not deregister A: {still_a!r}"
    )

    # The neighbouring constraint is a DIFFERENT error: same name, fresh ARN.
    name_code, name_message = _error(
        lambda: cd.register_on_premises_instance(
            instanceName=name_a, iamUserArn=arn_other
        )
    )
    assert name_code == "InstanceNameAlreadyRegisteredException", (
        f"reusing a registered instanceName must raise "
        f"InstanceNameAlreadyRegisteredException -- distinct from the iamUserArn "
        f"conflict above -- got {name_code!r}"
    )
    assert name_message == "Host name has already been registered or recently deregistered", name_message
    rebound = cd.get_on_premises_instance(instanceName=name_a)["instanceInfo"]
    assert rebound.get("iamUserArn") == arn_shared, (
        f"a refused re-registration must not rebind the ARN, got "
        f"{rebound.get('iamUserArn')!r} instead of {arn_shared!r}"
    )

    # The control still works: a fresh name with a fresh ARN is accepted.
    cd.register_on_premises_instance(instanceName=name_c, iamUserArn=arn_other)
    _register_onprem_teardown(ctx, cd, name_c)
    info_c = cd.get_on_premises_instance(instanceName=name_c)["instanceInfo"]
    assert info_c.get("iamUserArn") == arn_other, info_c
    final = _list_onprem(cd, "Registered")
    assert {name_a, name_c} <= final, (
        f"both A and C must be Registered, listing has {sorted(final & {name_a, name_b, name_c})!r}"
    )
    assert name_b not in final, (
        f"{name_b} must never exist: the ARN-reuse registration was refused"
    )

    # And the ARN freed by deregistering C becomes reusable -- the constraint is on
    # *live* registrations, not on history.
    cd.deregister_on_premises_instance(instanceName=name_c)
    deregistered = _list_onprem(cd, "Registered")
    assert name_c not in deregistered, (
        f"{name_c} must drop out of the Registered listing once deregistered, got "
        f"{sorted(deregistered & {name_a, name_c})!r}"
    )
    # After deregistering C, its iamUserArn is registrable again (the uniqueness
    # constraint is scoped to live registrations): a refusal here raises and fails.
    cd.register_on_premises_instance(instanceName=name_b, iamUserArn=arn_other)
    info_b = cd.get_on_premises_instance(instanceName=name_b)["instanceInfo"]
    assert info_b.get("iamUserArn") == arn_other, info_b


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)


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


def _account_id(ctx):
    cached = getattr(ctx, "_cd_account_id", None)
    if cached:
        return cached
    acct = ctx.client("sts").get_caller_identity()["Account"]
    ctx._cd_account_id = acct
    return acct


def _iam_user_arn(ctx, suffix):
    """A syntactically valid IAM user ARN. RegisterOnPremisesInstance accepts an ARN for
    a user that does not exist, so nothing is created in IAM."""
    return f"arn:aws:iam::{_account_id(ctx)}:user/{suffix}"


def _list_onprem(cd, registration_status, tag_filters=None):
    """Every on-premises instance name for a registration status, paginated, as a set."""
    names = set()
    token = None
    while True:
        kwargs = {"registrationStatus": registration_status}
        if tag_filters:
            kwargs["tagFilters"] = tag_filters
        if token:
            kwargs["nextToken"] = token
        page = cd.list_on_premises_instances(**kwargs)
        names.update(page.get("instanceNames") or [])
        token = page.get("nextToken")
        if not token:
            return names


def _register_onprem_teardown(ctx, cd, name):
    """Deregister at teardown. Registered at the point the name is minted, before the
    create is attempted, so a registration that unexpectedly succeeds cannot leak.
    Polls to the actual deregistered state instead of firing a delete blind."""
    def _teardown():
        try:
            cd.deregister_on_premises_instance(instanceName=name)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code != "InstanceNotRegisteredException":
                raise
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            try:
                info = cd.get_on_premises_instance(instanceName=name)["instanceInfo"]
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") == (
                    "InstanceNotRegisteredException"
                ):
                    return
                raise
            if info.get("deregisterTime") is not None:
                return
            time.sleep(2)
        raise AssertionError(
            f"on-premises instance {name} never reached a deregistered state during "
            "teardown; it would remain registered in the account"
        )

    ctx.on_cleanup(_teardown)
