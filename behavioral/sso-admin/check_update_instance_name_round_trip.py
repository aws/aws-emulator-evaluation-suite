"""update-instance-name-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-instance-name-round-trip"
GROUP = "state"
SERVICES = ["sso-admin"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """UpdateInstance(Name=...) is reflected verbatim by both the immediate response of
    ListInstances and DescribeInstance, and restoring the original name round-trips cleanly."""
    sso = ctx.client("sso-admin")
    instance_arn = _get_instance_arn(ctx)

    original_name = sso.list_instances()["Instances"][0].get("Name")
    ctx.on_cleanup(lambda: sso.update_instance(InstanceArn=instance_arn, Name=original_name or ""))

    new_name = ctx.unique_name("sim2real-behav-instance-")
    sso.update_instance(InstanceArn=instance_arn, Name=new_name)

    listed = next(i for i in sso.list_instances()["Instances"] if i["InstanceArn"] == instance_arn)
    assert listed["Name"] == new_name, f"expected ListInstances to reflect {new_name!r}, got {listed['Name']!r}"

    described = sso.describe_instance(InstanceArn=instance_arn)
    assert described["Name"] == new_name, f"expected DescribeInstance to reflect {new_name!r}, got {described['Name']!r}"

    # Renaming again with a second unique value reflects the *latest* write, not the first.
    second_name = ctx.unique_name("sim2real-behav-instance-2-")
    sso.update_instance(InstanceArn=instance_arn, Name=second_name)
    described_again = sso.describe_instance(InstanceArn=instance_arn)
    assert described_again["Name"] == second_name, (
        f"expected DescribeInstance to reflect the latest write {second_name!r}, got {described_again['Name']!r}"
    )
    assert described_again["Name"] != new_name, (
        f"DescribeInstance still returned the stale first name {new_name!r} after a second UpdateInstance"
    )


def _get_instance_arn(ctx):
    import time

    sso = ctx.client("sso-admin")
    instances = sso.list_instances().get("Instances", [])
    if instances:
        instance_arn = instances[0]["InstanceArn"]
    else:
        # Exactly one IAM Identity Center instance is allowed per account, and deleting it
        # would disrupt any other check relying on it, so if we must create one here we
        # deliberately never tear it down.
        instance_arn = sso.create_instance()["InstanceArn"]
    deadline = time.time() + 120
    status = None
    while time.time() < deadline:
        status = sso.describe_instance(InstanceArn=instance_arn)["Status"]
        if status == "ACTIVE":
            return instance_arn
        if status in ("CREATE_FAILED", "DELETE_IN_PROGRESS"):
            raise RuntimeError(f"IAM Identity Center instance in unexpected state: {status}")
        time.sleep(3)
    raise RuntimeError(f"IAM Identity Center instance did not become ACTIVE in time (last status: {status})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

