"""e2e-audit-event-pipeline-blocked-for-new-account."""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-audit-event-pipeline-blocked-for-new-account"
GROUP = "e2e"
SERVICES = ["cloudtrail-data"]


@tags("axis:rejection", "cap:c1", "concern:e2e", "concern:negative-classes", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """Walks CreateEventDataStore -> CreateChannel -> PutAuditEvents; where the account cannot
    create a Lake store, each step fails with its own step-specific code and message. Where it
    can, the pipeline is built for real and PutAuditEvents must accept the event."""
    cloudtrail = ctx.client("cloudtrail")
    cloudtrail_data = ctx.client("cloudtrail-data")
    account_id = _account_id(ctx)

    eds_code, _eds_message, eds_arn = _try_create_eds(ctx, cloudtrail)
    assert eds_code == "InvalidParameterException" or eds_arn is not None, (
        f"CreateEventDataStore failed for an unexpected reason: {eds_code!r}"
    )

    if eds_arn is not None:
        # Accounts that are existing CloudTrail Lake customers can still create stores.
        ctx.on_cleanup(lambda: _delete_eds(cloudtrail, eds_arn))
        channel_arn = _create_custom_channel(ctx, cloudtrail, eds_arn)
        event_id = f"sim2real-{uuid.uuid4().hex}"
        resp = cloudtrail_data.put_audit_events(
            channelArn=channel_arn,
            auditEvents=[{"id": event_id, "eventData": json.dumps(_base_event_data(ctx))}],
        )
        assert resp["failed"] == [], f"expected no failed events, got {resp['failed']!r}"
        assert resp["successful"][0]["id"] == event_id, (
            f"expected the successful record to echo id {event_id!r}, got {resp['successful']!r}"
        )
        return

    channel_name = ctx.unique_name("sim2real-e2e-ch-")
    phantom_eds_arn = (
        f"arn:aws:cloudtrail:{ctx.region}:{account_id}:eventdatastore/{uuid.uuid4()}"
    )
    channel_code, channel_message = _error(
        lambda: cloudtrail.create_channel(
            Name=channel_name,
            Source="Custom",
            Destinations=[{"Type": "EVENT_DATA_STORE", "Location": phantom_eds_arn}],
        )
    )
    assert channel_code == "EventDataStoreNotFoundException", (
        f"expected CreateChannel against a nonexistent event data store to fail with "
        f"EventDataStoreNotFoundException, got {channel_code!r}"
    )
    assert channel_message == f"The event data store {phantom_eds_arn} was not found.", (
        f"unexpected CreateChannel refusal message: {channel_message!r}"
    )
    channel_names = {c["Name"] for c in _list_all_channels(cloudtrail)}
    assert channel_name not in channel_names, (
        "a channel was created despite CreateChannel rejecting the request"
    )

    phantom_channel_arn = f"arn:aws:cloudtrail:{ctx.region}:{account_id}:channel/{uuid.uuid4()}"
    put_code, put_message = _error(
        lambda: cloudtrail_data.put_audit_events(
            channelArn=phantom_channel_arn,
            auditEvents=[{"id": f"sim2real-{uuid.uuid4().hex}", "eventData": json.dumps(_base_event_data(ctx))}],
        )
    )
    assert put_code == "ChannelNotFound", (
        f"expected the terminal PutAuditEvents step to fail with ChannelNotFound, got {put_code!r}"
    )
    assert put_message == f"The channel {phantom_channel_arn} could not be found.", (
        f"unexpected PutAuditEvents refusal message: {put_message!r}"
    )


def _try_create_eds(ctx, cloudtrail):
    name = ctx.unique_name("sim2real-cted-")
    try:
        resp = cloudtrail.create_event_data_store(
            Name=name,
            AdvancedEventSelectors=[
                {
                    "Name": "select-activity-audit-log",
                    "FieldSelectors": [{"Field": "eventCategory", "Equals": ["ActivityAuditLog"]}],
                }
            ],
            MultiRegionEnabled=False,
            RetentionPeriod=7,
            TerminationProtectionEnabled=False,
            TagsList=[{"Key": "sim2real", "Value": CHECK}, {"Key": "sim2real:managed", "Value": "true"}],
        )
        return None, None, resp["EventDataStoreArn"]
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message") or "", None


def _create_custom_channel(ctx, cloudtrail, eds_arn: str) -> str:
    name = ctx.unique_name("sim2real-ctc-")
    resp = cloudtrail.create_channel(
        Name=name,
        Source="Custom",
        Destinations=[{"Type": "EVENT_DATA_STORE", "Location": eds_arn}],
        Tags=[{"Key": "sim2real", "Value": CHECK}, {"Key": "sim2real:managed", "Value": "true"}],
    )
    arn = resp["ChannelArn"]
    ctx.on_cleanup(lambda: _delete_channel(cloudtrail, arn))
    return arn


def _delete_eds(cloudtrail, arn: str) -> None:
    try:
        cloudtrail.delete_event_data_store(EventDataStore=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EventDataStoreNotFoundException":
            raise


def _delete_channel(cloudtrail, arn: str) -> None:
    try:
        cloudtrail.delete_channel(Channel=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ChannelNotFoundException":
            raise


def _error(fn):
    """(Error.Code, Error.Message) for the ClientError fn() raises; a SUCCESS raises."""
    try:
        resp = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message") or ""
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {resp!r}")


def _list_all_channels(cloudtrail):
    channels = []
    token = None
    while True:
        kwargs = {"NextToken": token} if token else {}
        resp = cloudtrail.list_channels(**kwargs)
        channels.extend(resp.get("Channels", []))
        token = resp.get("NextToken")
        if not token:
            break
    return channels


def _now_ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")


def _account_id(ctx) -> str:
    return ctx.client("sts").get_caller_identity()["Account"]


def _base_event_data(ctx, **overrides) -> dict:
    data = {
        "version": "1.0",
        "userIdentity": {"type": "CustomUserIdentity", "principalId": "sim2real-principal"},
        "eventSource": "sim2real.example.com",
        "eventName": "Sim2RealTestAction",
        "eventTime": _now_ts(),
        "UID": f"sim2real-uid-{uuid.uuid4().hex}",
        "recipientAccountId": _account_id(ctx),
    }
    data.update(overrides)
    return data


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
