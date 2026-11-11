"""delete-config-then-get-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-config-then-get-not-found"
GROUP = "state"
SERVICES = ["groundstation"]


def _error(fn):
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises, because an
    emulator resurrecting a deleted resource is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """After DeleteConfig succeeds, GetConfig on the same id/type raises ResourceNotFoundException,
    and a subsequent mutation (UpdateConfig) on the same dead id is rejected too -- the deletion is
    not just invisible to reads, the identity is unusable outright."""
    gs = ctx.client("groundstation")
    name = ctx.unique_name("sim2real-gs-del-")
    created = gs.create_config(
        name=name,
        configData={"trackingConfig": {"autotrack": "PREFERRED"}},
    )
    config_id = created["configId"]
    config_type = created["configType"]

    def _cleanup():
        try:
            gs.delete_config(configId=config_id, configType=config_type)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)

    # Positive control: it exists before delete, and GetConfig returns the record we created.
    before = gs.get_config(configId=config_id, configType=config_type)
    assert before["configId"] == config_id, (
        f"positive control: GetConfig returned configId {before['configId']!r}, expected {config_id!r}"
    )

    gs.delete_config(configId=config_id, configType=config_type)

    code, message = _error(lambda: gs.get_config(configId=config_id, configType=config_type))
    assert code == "ResourceNotFoundException", (
        f"GetConfig after delete returned code {code!r}, expected ResourceNotFoundException"
    )
    expected_get = f"No config found with id {config_id} and type {config_type}"
    assert message == expected_get, (
        f"GetConfig after delete returned message {message!r}, expected {expected_get!r}"
    )

    # The dead id is not just absent from reads -- a mutation against it is rejected too.
    update_code, update_message = _error(lambda: gs.update_config(
        configId=config_id,
        configType=config_type,
        name=name,
        configData={"trackingConfig": {"autotrack": "PREFERRED"}},
    ))
    assert update_code == "ResourceNotFoundException", (
        f"UpdateConfig on a deleted configId returned code {update_code!r}, expected "
        f"ResourceNotFoundException"
    )
    expected_update = (
        f"No config found with ID {config_id} and type {config_type} for customer {ctx.account}"
    )
    assert update_message == expected_update, (
        f"UpdateConfig on a deleted configId returned message {update_message!r}, expected "
        f"{expected_update!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
