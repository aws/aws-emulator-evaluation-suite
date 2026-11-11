"""event-log-configuration-lifecycle-and-duplicate-conflict."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "event-log-configuration-lifecycle-and-duplicate-conflict"
GROUP = "crud-depth"
SERVICES = ["iot-managed-integrations"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:iotmi-event-log-configuration")
def run(ctx) -> None:
    """An event log configuration round-trips INFO then DEBUG; a duplicate fails with
    ConflictException 'Log configuration already exists.' and adds nothing; after delete Get
    and Update fail with ResourceNotFoundException and the create succeeds."""
    iot = _iot_client(ctx)

    created = iot.create_event_log_configuration(ResourceType="*", EventLogLevel="INFO")
    config_id = created["Id"]
    ctx.on_cleanup(lambda: _delete_config_ignore_missing(iot, config_id))

    got = iot.get_event_log_configuration(Id=config_id)
    assert got["ResourceType"] == "*"
    assert got["EventLogLevel"] == "INFO"

    iot.update_event_log_configuration(Id=config_id, EventLogLevel="DEBUG")
    updated = iot.get_event_log_configuration(Id=config_id)
    assert updated["EventLogLevel"] == "DEBUG"

    before = _wildcard_config_ids(iot)
    dup_code, dup_code_msg = _error(
        lambda: iot.create_event_log_configuration(ResourceType="*", EventLogLevel="WARN")
    )
    assert dup_code == "ConflictException", dup_code
    assert dup_code_msg == 'Log configuration already exists.', dup_code_msg
    after = _wildcard_config_ids(iot)
    assert after == before == {config_id}, (
        f"duplicate resource-type/id pair must not create a second config; "
        f"expected only {config_id!r} for ResourceType '*', got {before!r} then {after!r}"
    )

    iot.delete_event_log_configuration(Id=config_id)
    not_found_code, not_found_code_msg = _error(lambda: iot.get_event_log_configuration(Id=config_id))
    assert not_found_code == "ResourceNotFoundException", not_found_code
    assert not_found_code_msg == "Event log configuration doesn't exist", not_found_code_msg
    dead_update_code, dead_update_code_msg = _error(
        lambda: iot.update_event_log_configuration(Id=config_id, EventLogLevel="INFO")
    )
    assert dead_update_code == "ResourceNotFoundException", dead_update_code
    assert dead_update_code_msg is None, dead_update_code_msg

    restored = iot.create_event_log_configuration(ResourceType="*", EventLogLevel="WARN")
    restored_id = restored["Id"]
    ctx.on_cleanup(lambda: _delete_config_ignore_missing(iot, restored_id))
    assert restored_id != config_id, "restore leg must mint a fresh config, not resurrect the deleted one"
    restored_got = iot.get_event_log_configuration(Id=restored_id)
    assert restored_got["EventLogLevel"] == "WARN"


def _wildcard_config_ids(iot) -> set[str]:
    """Ids of the account's ResourceType '*' event log configurations, read across all pages."""
    return {
        c["Id"]
        for page in iot.get_paginator("list_event_log_configurations").paginate()
        for c in page.get("EventLogConfigurationList", [])
        if c.get("ResourceType") == "*"
    }


def _iot_client(ctx):
    # iot-managed-integrations is offered in ca-central-1 and eu-west-1 only, so this client
    # pins the region; ctx.client keeps the run's credentials and endpoint routing.
    return ctx.client("iot-managed-integrations", region="eu-west-1")
def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _delete_config_ignore_missing(iot, config_id: str) -> None:
    try:
        iot.delete_event_log_configuration(Id=config_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
