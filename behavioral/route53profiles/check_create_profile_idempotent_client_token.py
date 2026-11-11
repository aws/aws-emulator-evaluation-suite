"""create-profile-idempotent-client-token."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-profile-idempotent-client-token"
GROUP = "state"
SERVICES = ["route53profiles"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Retrying CreateProfile with the same ClientToken and Name returns the original Profile, not a duplicate."""
    r53p = ctx.client("route53profiles")
    name = ctx.unique_name("sim2real-behav-profile-")
    token = ctx.unique_name("sim2real-behav-token-")
    tags_spec = [{"Key": "sim2real-check", "Value": CHECK}]

    first = r53p.create_profile(Name=name, ClientToken=token, Tags=tags_spec)["Profile"]
    profile_id = first["Id"]
    ctx.on_cleanup(lambda: r53p.delete_profile(ProfileId=profile_id))

    second = r53p.create_profile(Name=name, ClientToken=token, Tags=tags_spec)["Profile"]

    assert second["Id"] == profile_id, (
        f"retry with identical ClientToken created a distinct Profile: {second['Id']!r} != {profile_id!r}"
    )
    assert second["Name"] == name, f"retried create returned Name {second['Name']!r}, expected {name!r}"
    assert second["Arn"] == first["Arn"], (
        f"retry returned a different Arn, implying a new resource: {second['Arn']!r} != {first['Arn']!r}"
    )
    assert second["CreationTime"] == first["CreationTime"], (
        "retry returned a different CreationTime, implying a new resource: "
        f"{second['CreationTime']!r} != {first['CreationTime']!r}"
    )

    listing = r53p.list_profiles()["ProfileSummaries"]
    matching = [p for p in listing if p["Id"] == profile_id]
    assert len(matching) == 1, (
        f"idempotent retry left {len(matching)} Profiles with Id {profile_id!r}, expected exactly 1"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
