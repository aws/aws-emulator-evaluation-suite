"""security-requirement-pack-disabled-status-at-creation."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "security-requirement-pack-disabled-status-at-creation"
GROUP = "state"
SERVICES = ["securityagent"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Creating a pack with status=DISABLED persists DISABLED (not the ENABLED default)."""
    sa = ctx.client("securityagent")
    name = ctx.unique_name("sim2real-behav-pack-")

    created = sa.create_security_requirement_pack(
        name=name, status="DISABLED", tags={"sim2real": "audit"}
    )
    assert created["status"] == "DISABLED", f"expected DISABLED at creation, got {created['status']!r}"
    pack_id = created["packId"]

    def _cleanup():
        try:
            sa.delete_security_requirement_pack(packId=pack_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)

    got = sa.get_security_requirement_pack(packId=pack_id)
    assert got["status"] == "DISABLED", f"expected DISABLED to persist, got {got['status']!r}"

    sa.delete_security_requirement_pack(packId=pack_id)
    try:
        sa.get_security_requirement_pack(packId=pack_id)
        raise AssertionError("expected ResourceNotFoundException after delete, got a successful get")
    except ClientError as e:
        code = e.response["Error"]["Code"]
        assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
        message = e.response["Error"].get("Message")
        expected = f"No security requirement pack found for ID: {pack_id}"
        assert message == expected, f"expected message {expected!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
