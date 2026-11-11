"""security-requirement-pack-lifecycle-crud."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "security-requirement-pack-lifecycle-crud"
GROUP = "state"
SERVICES = ["securityagent"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Create defaults to ENABLED, Get reflects it, Delete removes it (Get 404s after, second Delete 404s too)."""
    sa = ctx.client("securityagent")
    name = ctx.unique_name("sim2real-behav-pack-")

    created = sa.create_security_requirement_pack(
        name=name, tags={"sim2real": "security-requirement-pack-lifecycle-crud"}
    )
    assert created["status"] == "ENABLED", f"expected ENABLED default status, got {created['status']!r}"
    pack_id = created["packId"]

    def _cleanup():
        try:
            sa.delete_security_requirement_pack(packId=pack_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)

    got = sa.get_security_requirement_pack(packId=pack_id)
    assert got["name"] == name, f"expected name {name!r}, got {got['name']!r}"
    assert got["status"] == "ENABLED", f"expected ENABLED status on read-back, got {got['status']!r}"
    assert got["managementType"] == "CUSTOMER_MANAGED", (
        f"expected CUSTOMER_MANAGED for a self-created pack, got {got['managementType']!r}"
    )

    sa.delete_security_requirement_pack(packId=pack_id)

    try:
        sa.get_security_requirement_pack(packId=pack_id)
        raise AssertionError("expected ResourceNotFoundException from Get after delete")
    except ClientError as e:
        code = e.response["Error"]["Code"]
        assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException from Get after delete, got {code!r}"
        message = e.response["Error"].get("Message")
        expected = f"No security requirement pack found for ID: {pack_id}"
        assert message == expected, f"expected message {expected!r}, got {message!r}"

    try:
        sa.delete_security_requirement_pack(packId=pack_id)
        raise AssertionError("expected ResourceNotFoundException from a second Delete on the same id")
    except ClientError as e:
        code = e.response["Error"]["Code"]
        assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException from second Delete, got {code!r}"
        message = e.response["Error"].get("Message")
        expected = f"No security requirement pack found for ID: {pack_id}"
        assert message == expected, f"expected message {expected!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
