"""create-get-instance-profile."""
from __future__ import annotations

from behavioral_harness import tags


CHECK = "create-get-instance-profile"
GROUP = 'instance_profiles'
SERVICES = ['iam']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateInstanceProfile -> GetInstanceProfile returns consistent data."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-ip-")
    created = iam.create_instance_profile(
        InstanceProfileName=name, Path="/", Tags=[{"Key": "sim2real", "Value": CHECK}]
    )["InstanceProfile"]
    ctx.on_cleanup(lambda n=name: iam.delete_instance_profile(InstanceProfileName=n))
    resp = iam.get_instance_profile(InstanceProfileName=name)
    ip = resp["InstanceProfile"]
    assert ip["InstanceProfileName"] == name, (
        f"expected InstanceProfileName {name!r}, got {ip['InstanceProfileName']!r}"
    )
    assert ip["Path"] == "/", f"expected Path '/', got {ip['Path']!r}"
    assert ip["Arn"] == created["Arn"], (
        f"GetInstanceProfile Arn {ip['Arn']!r} != CreateInstanceProfile Arn {created['Arn']!r}"
    )
    assert ip["InstanceProfileId"] == created["InstanceProfileId"], (
        f"GetInstanceProfile InstanceProfileId {ip['InstanceProfileId']!r} != "
        f"CreateInstanceProfile InstanceProfileId {created['InstanceProfileId']!r}"
    )
    assert ip["Roles"] == [], f"expected no roles on a freshly created profile, got {ip['Roles']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
