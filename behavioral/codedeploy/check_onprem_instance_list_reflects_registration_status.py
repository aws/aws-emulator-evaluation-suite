"""onprem-instance-list-reflects-registration-status."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "onprem-instance-list-reflects-registration-status"
GROUP = "state-machine"
SERVICES = ["codedeploy"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """The Registered filter of ListOnPremisesInstances lists both registered instances, drops
    one once it is deregistered, and keeps its still-active twin, which the Deregistered filter
    never lists."""
    cd = ctx.client("codedeploy")

    tag_value = ctx.unique_name("cd-reglifecycle")
    registered_name = _register_onprem_instance(ctx, "reg-a", tag_value)
    deregistered_name = _register_onprem_instance(ctx, "reg-b", tag_value)

    tag_filters = [{"Key": "sim2real-tag", "Value": tag_value, "Type": "KEY_AND_VALUE"}]

    def registered_set():
        return set(_list_all(cd, registrationStatus="Registered", tagFilters=tag_filters))

    # Both instances show up as Registered promptly after registration.
    both_present = _poll_until(
        registered_set,
        lambda names: registered_name in names and deregistered_name in names,
        timeout_s=60.0,
        interval_s=3.0,
    )
    assert registered_name in both_present, (
        f"{registered_name} must appear under registrationStatus='Registered' shortly "
        f"after registration, got {both_present!r}"
    )
    assert deregistered_name in both_present, (
        f"{deregistered_name} must appear under registrationStatus='Registered' shortly "
        f"after registration, got {both_present!r}"
    )

    cd.deregister_on_premises_instance(instanceName=deregistered_name)

    # Deregistration removes the instance from the Registered bucket promptly; the
    # still-active instance remains.
    after_dereg = _poll_until(
        registered_set,
        lambda names: deregistered_name not in names,
        timeout_s=60.0,
        interval_s=3.0,
    )
    assert deregistered_name not in after_dereg, (
        f"{deregistered_name} was deregistered, so it must drop out of "
        f"registrationStatus='Registered', got {after_dereg!r}"
    )
    assert registered_name in after_dereg, (
        f"deregistering {deregistered_name} must not evict the still-active "
        f"{registered_name} from registrationStatus='Registered', got {after_dereg!r}"
    )

    # Deregister purges the record rather than moving it to "Deregistered", so only the
    # still-active instance's absence from that bucket is asserted.
    deregistered_bucket = _list_all(cd, registrationStatus="Deregistered")
    assert registered_name not in deregistered_bucket, (
        f"{registered_name} is still actively registered, so registrationStatus="
        f"'Deregistered' must not list it, got {deregistered_bucket!r}"
    )


def _poll_until(probe, predicate, timeout_s=90.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _register_onprem_instance(ctx, suffix: str, tag_value: str) -> str:
    iam = ctx.client("iam")
    cd = ctx.client("codedeploy")
    user_name = ctx.unique_name(f"sim2real-cdonprem-user-{suffix}-")
    user_arn = iam.create_user(
        UserName=user_name,
        Tags=[{"Key": "sim2real-tag", "Value": tag_value}],
    )["User"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))
    instance_name = ctx.unique_name(f"sim2real-onprem-{suffix}-")
    cd.register_on_premises_instance(instanceName=instance_name, iamUserArn=user_arn)
    ctx.on_cleanup(lambda: cd.deregister_on_premises_instance(instanceName=instance_name))
    cd.add_tags_to_on_premises_instances(
        tags=[{"Key": "sim2real-tag", "Value": tag_value}], instanceNames=[instance_name]
    )
    return instance_name



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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

