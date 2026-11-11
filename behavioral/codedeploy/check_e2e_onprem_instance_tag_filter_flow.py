"""e2e-onprem-instance-tag-filter-flow."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "e2e-onprem-instance-tag-filter-flow"
GROUP = "e2e"
SERVICES = ["codedeploy"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Register an on-premises instance, tag it, confirm it is returned by
    ListOnPremisesInstances filtered on that tag while Registered, deregister it, and
    confirm it disappears from that same filtered+Registered-status view."""
    codedeploy = ctx.client("codedeploy")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    instance_name = ctx.unique_name("sim2real-onprem-")
    iam_user_arn = f"arn:aws:iam::{account_id}:user/{ctx.unique_name('sim2real-user-')}"
    tag_key = "sim2real-flow-key"
    tag_value = ctx.unique_name("sim2real-flow-val-")

    codedeploy.register_on_premises_instance(instanceName=instance_name, iamUserArn=iam_user_arn)
    deregistered = {"done": False}

    def _cleanup():
        if not deregistered["done"]:
            codedeploy.deregister_on_premises_instance(instanceName=instance_name)

    ctx.on_cleanup(_cleanup)

    codedeploy.add_tags_to_on_premises_instances(
        tags=[{"Key": tag_key, "Value": tag_value}], instanceNames=[instance_name]
    )

    tag_filters = [{"Key": tag_key, "Value": tag_value, "Type": "KEY_AND_VALUE"}]
    last_names: dict = {"value": None}

    def _filtered_names():
        names = codedeploy.list_on_premises_instances(
            registrationStatus="Registered", tagFilters=tag_filters
        )["instanceNames"]
        last_names["value"] = names
        return names

    def _present():
        return instance_name in _filtered_names()

    assert _poll_until(_present, timeout_s=30, interval_s=2), (
        f"registered+tagged instance {instance_name!r} never appeared in the filtered "
        f"Registered list; last observed {last_names['value']!r}"
    )

    codedeploy.deregister_on_premises_instance(instanceName=instance_name)
    deregistered["done"] = True

    def _absent():
        return instance_name not in _filtered_names()

    assert _poll_until(_absent, timeout_s=30, interval_s=2), (
        f"deregistered instance {instance_name!r} still appeared in the Registered-status "
        f"filtered list: {last_names['value']!r}"
    )


def _poll_until(probe, *, timeout_s: float, interval_s: float) -> bool:
    deadline = time.monotonic() + timeout_s
    while True:
        if probe():
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
