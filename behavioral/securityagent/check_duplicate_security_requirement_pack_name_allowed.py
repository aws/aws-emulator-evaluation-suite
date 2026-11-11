"""duplicate-security-requirement-pack-name-allowed."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "duplicate-security-requirement-pack-name-allowed"
GROUP = "state"
SERVICES = ["securityagent"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A second CreateSecurityRequirementPack with an existing name gets its own packId and both packs
    are listed under that name; deleting one makes it ResourceNotFoundException while the other stays
    ENABLED with the same name."""
    sa = ctx.client("securityagent")
    name = ctx.unique_name("sim2real-behav-pack-")

    original = sa.create_security_requirement_pack(name=name, tags={"sim2real": CHECK})
    pack_id_1 = original["packId"]

    def _cleanup_1():
        try:
            sa.delete_security_requirement_pack(packId=pack_id_1)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup_1)

    second = sa.create_security_requirement_pack(name=name, tags={"sim2real": CHECK})
    pack_id_2 = second["packId"]
    ctx.on_cleanup(lambda: sa.delete_security_requirement_pack(packId=pack_id_2))

    assert pack_id_1 != pack_id_2, (
        f"expected distinct packIds for two same-name creates, got {pack_id_1!r} twice"
    )

    # both packs coexist with the same name, independently addressable
    matches = {p["packId"] for p in _list_all_packs(sa) if p["name"] == name}
    assert matches == {pack_id_1, pack_id_2}, (
        f"expected list to show both {pack_id_1!r} and {pack_id_2!r} under name {name!r}, "
        f"got {matches!r}"
    )

    # deleting one leaves the other fully intact (isolation boundary), and the deleted
    # one is actually gone rather than merely unlinked from the list
    sa.delete_security_requirement_pack(packId=pack_id_1)

    try:
        sa.get_security_requirement_pack(packId=pack_id_1)
        raise AssertionError(f"expected ResourceNotFoundException for deleted {pack_id_1!r}")
    except ClientError as e:
        code = e.response["Error"]["Code"]
        assert code == "ResourceNotFoundException", (
            f"expected ResourceNotFoundException for deleted {pack_id_1!r}, got {code!r}"
        )
        message = e.response["Error"].get("Message")
        expected = f"No security requirement pack found for ID: {pack_id_1}"
        assert message == expected, f"expected {expected!r}, got {message!r}"

    still_there = sa.get_security_requirement_pack(packId=pack_id_2)
    assert still_there["name"] == name, (
        f"expected surviving pack {pack_id_2!r} to keep name {name!r}, got {still_there['name']!r}"
    )
    assert still_there["status"] == "ENABLED", (
        f"expected surviving pack {pack_id_2!r} to remain ENABLED, got {still_there['status']!r}"
    )


def _list_all_packs(sa) -> list[dict]:
    """Every pack summary across ListSecurityRequirementPacks pages."""
    packs: list[dict] = []
    kwargs: dict = {}
    while True:
        page = sa.list_security_requirement_packs(**kwargs)
        packs.extend(page["securityRequirementPackSummaries"])
        token = page.get("nextToken")
        if not token:
            return packs
        kwargs["nextToken"] = token


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

