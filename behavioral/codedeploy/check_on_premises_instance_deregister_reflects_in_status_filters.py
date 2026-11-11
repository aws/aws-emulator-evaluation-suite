"""on-premises-instance-deregister-reflects-in-status-filters."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "on-premises-instance-deregister-reflects-in-status-filters"
GROUP = 'lifecycle'
SERVICES = ['codedeploy']


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A registered, tagged on-premises instance is listed as Registered and readable; after
    Deregister the record is purged (Get raises InstanceNotRegisteredException, neither status
    lists it), and re-registering the name mints a new instanceArn with no tags."""
    cd = ctx.client("codedeploy")

    name = ctx.unique_name("sim2real-behav-cd-onprem-")
    # A per-run tag value keeps the account-wide ListOnPremisesInstances deterministic
    # under concurrency.
    tag_key = "sim2real:onprem-run"
    tag_value = name
    tag = {"Key": tag_key, "Value": tag_value}

    cd.register_on_premises_instance(
        instanceName=name, iamUserArn=_iam_user_arn(ctx, name)
    )
    _register_onprem_teardown(ctx, cd, name)

    cd.add_tags_to_on_premises_instances(tags=[tag], instanceNames=[name])

    registered = cd.get_on_premises_instance(instanceName=name)["instanceInfo"]
    assert registered.get("instanceName") == name, registered
    assert registered.get("registerTime") is not None, (
        f"a registered instance must report a registerTime: {registered!r}"
    )
    # The instanceArn is minted per REGISTRATION, not per name: it is the name with a
    # service-generated suffix. The re-registration leg below turns on this.
    first_arn = registered.get("instanceArn") or ""
    assert f":instance/{name}_" in first_arn, (
        f"the instanceArn must be scoped to this registration as "
        f"arn:...:instance/<name>_<suffix>, got {first_arn!r}"
    )
    assert registered.get("deregisterTime") is None, (
        f"a still-registered instance must not report a deregisterTime, got "
        f"{registered.get('deregisterTime')!r}"
    )
    assert registered.get("tags") == [tag], (
        f"AddTagsToOnPremisesInstances must be readable back verbatim, got "
        f"{registered.get('tags')!r}"
    )

    # Present under the Registered status, selected by tag.
    assert name in _list_onprem(cd, "Registered", tag_filters=[
        {"Key": tag_key, "Value": tag_value, "Type": "KEY_AND_VALUE"}
    ]), (
        f"{name} must be returned by ListOnPremisesInstances("
        "registrationStatus='Registered') under its own tag filter"
    )
    # and absent from the Deregistered status.
    assert name not in _list_onprem(cd, "Deregistered"), (
        f"{name} is registered, so it must not appear under "
        "registrationStatus='Deregistered'"
    )

    cd.deregister_on_premises_instance(instanceName=name)

    # Deregistration PURGES the record: Get no longer resolves the host at all.
    gone_code, gone_message = _error(
        lambda: cd.get_on_premises_instance(instanceName=name)
    )
    assert gone_code == "InstanceNotRegisteredException", (
        f"after DeregisterOnPremisesInstance the record is deleted, so "
        f"GetOnPremisesInstance must raise InstanceNotRegisteredException, got "
        f"{gone_code!r}"
    )
    assert gone_message == f"The requested host does not exist. Host: {name}", gone_message

    # The status filters: it leaves 'Registered' and does NOT arrive in 'Deregistered'.
    # Held past the deregistration rather than sampled once, because "absent from both"
    # would also be the transient state of an eventually-consistent transition -- this
    # asserts it is the STEADY state. 'Deregistered' is exercised as a live filter (the
    # call must succeed and be a well-formed listing) so that an emulator rejecting the
    # enum member cannot pass by returning nothing.
    _hold_absent(cd, name, seconds=30)

    # The purge is a DELETE, not a hide: the same name can be registered again, and the
    # new record is demonstrably new -- a fresh instanceArn suffix, an empty tag list, and
    # a later registerTime. An emulator that merely marks the record invisible fails here.
    cd.register_on_premises_instance(
        instanceName=name, iamUserArn=_iam_user_arn(ctx, name)
    )
    reborn = cd.get_on_premises_instance(instanceName=name)["instanceInfo"]
    assert reborn.get("instanceArn") != first_arn, (
        f"re-registering a deregistered name must mint a NEW instanceArn, but the old "
        f"one came back: {first_arn!r}"
    )
    assert f":instance/{name}_" in (reborn.get("instanceArn") or ""), (
        f"the new instanceArn must still be scoped to the name, got "
        f"{reborn.get('instanceArn')!r}"
    )
    assert (reborn.get("tags") or []) == [], (
        f"the tags applied to the previous registration must not survive it, got "
        f"{reborn.get('tags')!r}"
    )
    assert reborn.get("registerTime") > registered.get("registerTime"), (
        f"the new registration must carry a later registerTime than the purged one: "
        f"{reborn.get('registerTime')!r} vs {registered.get('registerTime')!r}"
    )
    assert reborn.get("deregisterTime") is None, (
        f"a freshly registered instance must not report a deregisterTime, got "
        f"{reborn.get('deregisterTime')!r}"
    )
    assert name in _list_onprem(cd, "Registered"), (
        f"{name} was registered again, so registrationStatus='Registered' must include it"
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


def _hold_absent(cd, name, *, seconds, interval_s=3):
    """Assert `name` is in NEITHER status listing, continuously, for `seconds`.

    Sampling once cannot distinguish a purge from the in-between moment of an
    eventually-consistent transition into 'Deregistered'. Holding does.
    """
    deadline = time.monotonic() + seconds
    while True:
        for status in ("Registered", "Deregistered"):
            listed = _list_onprem(cd, status)
            assert name not in listed, (
                f"DeregisterOnPremisesInstance deletes the record, so {name} must not "
                f"appear under registrationStatus={status!r}; it did, {seconds}s-hold "
                f"aborted with {len(listed)} names listed"
            )
        if time.monotonic() >= deadline:
            return
        time.sleep(interval_s)


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
    """Deregister at teardown. Poll to the deregistered state rather than firing a
    delete blind: a registration that is mid-create cannot be deregistered, and a
    swallowed teardown exception would leak the record into the account."""
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

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
