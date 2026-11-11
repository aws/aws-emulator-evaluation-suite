"""configuration-update-rejected-while-deleting."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "configuration-update-rejected-while-deleting"
GROUP = 'overly-permissive'
SERVICES = ['kafka']

_PROPS = b"auto.create.topics.enable=true\n"
_KAFKA_VERSION = "3.9.x"

# UpdateConfiguration is refused with
# BadRequestException/400 both while the configuration is DELETING and after it is gone, but the
# MESSAGE discriminates the two, and that distinction is the whole point of this check: the
# DELETING refusal is a state-machine refusal, the post-delete one is a lookup miss.
_DELETING_MSG = "This operation is only valid for resources that are in one of the following states :[ACTIVE]"
_GONE_MSG = "Configuration ARN does not exist."


def _poll(fn, pred, *, timeout_s, interval_s, description="condition"):
    deadline = time.monotonic() + timeout_s
    val = fn()
    while not pred(val):
        if time.monotonic() >= deadline:
            raise AssertionError(f"{description} not met within {timeout_s}s; last={val!r}")
        time.sleep(interval_s)
        val = fn()
    return val


def _fail(fn):
    """Invoke fn(); return (error_code, http_status, message). Raise if it unexpectedly succeeds."""
    try:
        resp = fn()
    except ClientError as exc:
        return (
            exc.response.get("Error", {}).get("Code"),
            exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode"),
            exc.response.get("Error", {}).get("Message") or "",
        )
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {resp}")


def _delete_unless_gone(msk, arn):
    """Teardown: delete the configuration unless the check already deleted it."""
    try:
        msk.delete_configuration(Arn=arn)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Message") != _GONE_MSG:
            raise


def _paginate(fn, list_key, **kwargs):
    items, token = [], None
    for _ in range(200):
        page_kwargs = dict(kwargs)
        if token:
            page_kwargs["NextToken"] = token
        resp = fn(**page_kwargs)
        items.extend(resp.get(list_key, []))
        token = resp.get("NextToken")
        if not token:
            break
    return items


def _revision_count(msk, arn):
    """Revision count on a configuration, or the error Code once it is unreadable."""
    try:
        return len(_paginate(msk.list_configuration_revisions, "Revisions", Arn=arn))
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code")


def _describe_state(msk, arn):
    """Configuration State, or the error Code once the configuration is unreadable."""
    try:
        return msk.describe_configuration(Arn=arn)["State"]
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code", "ERROR")


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateConfiguration on a DELETING configuration fails with BadRequestException 400 and the
    ACTIVE-state message without a new revision; it stays listed as DELETING until gone, and an independent
    configuration still updates."""
    msk = ctx.client("kafka")

    # --- full valid setup: the update path demonstrably works on this ARN ------------
    victim_name = ctx.unique_name("sim2real-behav-config-deleting-")
    victim = msk.create_configuration(
        Name=victim_name, KafkaVersions=[_KAFKA_VERSION], ServerProperties=_PROPS
    )
    victim_arn = victim["Arn"]
    ctx.on_cleanup(lambda _a=victim_arn: _delete_unless_gone(msk, _a))
    _poll(
        lambda: msk.describe_configuration(Arn=victim_arn),
        lambda d: d.get("State") in ("ACTIVE", "DELETE_FAILED"),
        timeout_s=120,
        interval_s=3,
        description="configuration to reach ACTIVE",
    )
    bumped = msk.update_configuration(Arn=victim_arn, ServerProperties=_PROPS + b"num.partitions=2\n")
    assert bumped["LatestRevision"]["Revision"] == 2, bumped["LatestRevision"]
    revisions_before = _revision_count(msk, victim_arn)
    assert revisions_before == 2, f"expected 2 revisions before delete, got {revisions_before}"

    # --- break exactly one thing: delete it -----------------------------------------
    deleted = msk.delete_configuration(Arn=victim_arn)
    assert deleted["State"] == "DELETING", (
        f"DeleteConfiguration must report State=DELETING, got {deleted.get('State')}"
    )

    # --- the mutation must be refused, AND the refusal must be the STATE refusal ------
    code, status, msg = _fail(
        lambda: msk.update_configuration(
            Arn=victim_arn, ServerProperties=_PROPS + b"num.partitions=9\n"
        )
    )
    assert code == "BadRequestException", (
        f"UpdateConfiguration against a DELETING configuration must be BadRequestException, "
        f"got {code} (HTTP {status})"
    )
    assert status == 400, f"expected HTTP 400, got {status}"
    assert msg == _DELETING_MSG, (
        f"the refusal must be the state-machine refusal ({_DELETING_MSG!r}) -- an "
        f"implementation that erased the record synchronously reports it as a lookup miss "
        f"instead: {msg!r}"
    )

    # --- the effect must be absent: no new revision, no resurrection -----------------
    revisions_after = _revision_count(msk, victim_arn)
    assert revisions_after in (2, "BadRequestException", "NotFoundException"), (
        f"after the refused update the configuration reports {revisions_after!r} revisions; "
        f"a third revision means the rejected write landed anyway"
    )

    # DELETING is a visible state, not an erase: the configuration is still enumerable and
    # carries State=DELETING (read inside the delete window).
    listed = [
        c
        for c in _paginate(msk.list_configurations, "Configurations")
        if c["Name"] == victim_name
    ]
    assert listed, (
        f"{victim_name} must still be listed by ListConfigurations while its delete is in "
        f"flight -- an implementation that drops it from the listing immediately is erasing "
        f"the record instead of transitioning it"
    )
    assert listed[0]["State"] == "DELETING", (
        f"while the delete is in flight ListConfigurations must report the configuration "
        f"as DELETING, got {listed[0]['State']!r}"
    )

    state_after = _poll(
        lambda: _describe_state(msk, victim_arn),
        lambda s: s != "ACTIVE",
        timeout_s=120,
        interval_s=3,
        description="deleted configuration to stop reporting ACTIVE",
    )
    assert state_after != "ACTIVE", (
        f"the refused update resurrected the configuration to {state_after}"
    )

    # --- and once the async delete completes, the SAME update is refused differently ---
    _poll(
        lambda: {c["Name"] for c in _paginate(msk.list_configurations, "Configurations")},
        lambda names: victim_name not in names,
        timeout_s=180,
        interval_s=5,
        description=f"deleted configuration {victim_name} to leave ListConfigurations",
    )
    gone_code, gone_status, gone_msg = _fail(
        lambda: msk.update_configuration(
            Arn=victim_arn, ServerProperties=_PROPS + b"num.partitions=9\n"
        )
    )
    assert (gone_code, gone_status) == ("BadRequestException", 400), (
        f"UpdateConfiguration after the delete completed must still be BadRequestException/400, "
        f"got {gone_code} (HTTP {gone_status})"
    )
    assert gone_msg == _GONE_MSG, (
        f"once the configuration is gone the refusal must be the lookup miss {_GONE_MSG!r}, "
        f"not the DELETING state refusal: {gone_msg!r}"
    )

    # --- the control case must still work --------------------------------------------
    control_name = ctx.unique_name("sim2real-behav-config-deleting-control-")
    control = msk.create_configuration(
        Name=control_name, KafkaVersions=[_KAFKA_VERSION], ServerProperties=_PROPS
    )
    control_arn = control["Arn"]
    ctx.on_cleanup(lambda _a=control_arn: msk.delete_configuration(Arn=_a))
    control_update = msk.update_configuration(
        Arn=control_arn, ServerProperties=_PROPS + b"num.partitions=2\n"
    )
    assert control_update["LatestRevision"]["Revision"] == 2, control_update["LatestRevision"]
    control_revisions = _revision_count(msk, control_arn)
    assert control_revisions == 2, (
        f"expected 2 revisions on the independent control configuration after its update, "
        f"got {control_revisions!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
