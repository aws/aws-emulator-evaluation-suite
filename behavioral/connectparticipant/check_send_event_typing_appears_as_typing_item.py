"""send-event-typing-appears-as-typing-item."""
from __future__ import annotations

import json
import re
import time

from behavioral_harness import tags


CHECK = "send-event-typing-appears-as-typing-item"
GROUP = "data-plane"
SERVICES = ["connectparticipant"]
# Cost: nothing here is optional on any backend. A run creates one Connect instance and
# deletes it in its teardown.

# SendEventResponse.AbsoluteTime: "ISO 8601 format: yyyy-MM-ddThh:mm:ss.SSSZ".
_INSTANT = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z")


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """SendEvent(typing) answers an Id and a yyyy-MM-ddThh:mm:ss.SSSZ AbsoluteTime, and once a later message
    is in GetTranscript (as a CUSTOMER MESSAGE with SendMessage's AbsoluteTime) the transcript holds no
    item for the typing event: typing events are transient and never persist."""
    session = _setup_chat_session(ctx)
    cp = session["cp"]
    token = session["connection_token"]

    typing = cp.send_event(
        ContentType="application/vnd.amazonaws.connect.event.typing", ConnectionToken=token
    )
    typing_id = typing.get("Id")
    typing_time = typing.get("AbsoluteTime")
    assert typing_id, f"SendEvent returned no Id: {typing!r}"
    assert _INSTANT.fullmatch(typing_time or ""), f"AbsoluteTime is not yyyy-MM-ddThh:mm:ss.SSSZ: {typing_time!r}"

    fence = cp.send_message(
        ContentType="text/plain", Content=f"fence-{ctx.unique_name('')}", ConnectionToken=token
    )
    fence_id = fence["Id"]
    assert fence_id != typing_id, f"the message reused the typing event's Id {typing_id!r}"

    items = _poll_until(
        lambda: cp.get_transcript(ConnectionToken=token, MaxResults=100)["Transcript"],
        lambda items: any(i.get("Id") == fence_id for i in items),
        timeout_s=30,
        interval_s=2,
    )
    message = next(i for i in items if i["Id"] == fence_id)
    assert message["Type"] == "MESSAGE", f"expected the fence as a MESSAGE item, got {message!r}"
    assert message["ParticipantRole"] == "CUSTOMER", f"expected ParticipantRole CUSTOMER, got {message!r}"
    assert message["AbsoluteTime"] == fence["AbsoluteTime"], (
        f"transcript AbsoluteTime {message['AbsoluteTime']!r} != SendMessage's {fence['AbsoluteTime']!r}"
    )
    assert typing_time <= message["AbsoluteTime"], (
        f"typing AbsoluteTime {typing_time!r} is after the later message's {message['AbsoluteTime']!r}"
    )
    typing_items = [
        i
        for i in items
        if i.get("Id") == typing_id
        or i.get("Type") == "TYPING"
        or i.get("ContentType") == "application/vnd.amazonaws.connect.event.typing"
    ]
    assert not typing_items, f"GetTranscript lists the typing event: {typing_items!r}"


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


# Each run creates its own Connect instance and deletes it in its teardown. Connect limits how
# many instances an account creates or deletes in 30 days, so a run creates exactly one.
_CP_ALIAS_PREFIX = "sim2real-cprun-"
_CP_DELETE_TIMEOUT_S = 300.0


def _flow_content() -> str:
    # A "Wait" action between the two reproducibly draws InvalidContactFlowException from
    # CreateContactFlow; this shape keeps the chat open long enough for every check here.
    msg_id = "11111111-1111-1111-1111-111111111111"
    disconnect_id = "33333333-3333-3333-3333-333333333333"
    return json.dumps(
        {
            "Version": "2019-10-30",
            "StartAction": msg_id,
            "Actions": [
                {
                    "Identifier": msg_id,
                    "Type": "MessageParticipant",
                    "Transitions": {"NextAction": disconnect_id, "Errors": [], "Conditions": []},
                    "Parameters": {"Text": "Hello, how can I help you today?"},
                },
                {
                    "Identifier": disconnect_id,
                    "Type": "DisconnectParticipant",
                    "Transitions": {},
                    "Parameters": {},
                },
            ],
        }
    )


def _code(err) -> str:
    return err.response.get("Error", {}).get("Code", "")


def _delete_instance(connect, instance_id: str) -> None:
    """DeleteInstance takes the instance's flows and chats with it, and the deletion is complete
    once DescribeInstance answers ResourceNotFoundException."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + _CP_DELETE_TIMEOUT_S
    while True:
        try:
            connect.delete_instance(InstanceId=instance_id)
            break
        except ClientError as err:
            if _code(err) == "ResourceNotFoundException":
                break
            # An instance still being created refuses deletion until its creation settles.
            if _code(err) != "InvalidRequestException" or time.monotonic() > deadline:
                raise
            time.sleep(15)
    while True:
        try:
            connect.describe_instance(InstanceId=instance_id)
        except ClientError as err:
            if _code(err) == "ResourceNotFoundException":
                return
            raise
        if time.monotonic() > deadline:
            raise AssertionError(
                f"Connect instance {instance_id} still exists {_CP_DELETE_TIMEOUT_S:.0f}s after DeleteInstance"
            )
        time.sleep(10)


def _create_instance(ctx, connect) -> str:
    """A new, ACTIVE Connect instance whose teardown is registered before anything can fail."""
    instance_id = connect.create_instance(
        IdentityManagementType="CONNECT_MANAGED",
        InstanceAlias=ctx.unique_name(_CP_ALIAS_PREFIX).lower()[:45],
        InboundCallsEnabled=True,
        OutboundCallsEnabled=True,
    )["Id"]
    ctx.on_cleanup(lambda: _delete_instance(connect, instance_id))
    status = _poll_until(
        lambda: connect.describe_instance(InstanceId=instance_id)["Instance"]["InstanceStatus"],
        lambda status: status != "CREATION_IN_PROGRESS",
        timeout_s=300,
        interval_s=5,
    )
    assert status == "ACTIVE", f"Connect instance {instance_id} ended {status!r}, not ACTIVE"
    return instance_id


def _start_chat_contact(ctx, display_name: str = "sim2real-customer") -> dict:
    connect = ctx.client("connect")
    cp = ctx.client("connectparticipant")
    instance_id = _create_instance(ctx, connect)
    contact_flow_id = connect.create_contact_flow(
        InstanceId=instance_id,
        Name=ctx.unique_name("sim2real-cprun-flow-"),
        Type="CONTACT_FLOW",
        Status="PUBLISHED",
        Content=_flow_content(),
    )["ContactFlowId"]
    chat = connect.start_chat_contact(
        InstanceId=instance_id,
        ContactFlowId=contact_flow_id,
        ParticipantDetails={"DisplayName": display_name},
        ChatDurationInMinutes=60,
    )
    return {
        "connect": connect,
        "cp": cp,
        "instance_id": instance_id,
        "contact_flow_id": contact_flow_id,
        "contact_id": chat["ContactId"],
        "participant_token": chat["ParticipantToken"],
    }


def _connect_participant(session: dict, types=("CONNECTION_CREDENTIALS",)) -> dict:
    resp = session["cp"].create_participant_connection(
        ParticipantToken=session["participant_token"], Type=list(types)
    )
    if "ConnectionCredentials" in resp:
        session["connection_token"] = resp["ConnectionCredentials"]["ConnectionToken"]
    return resp


def _setup_chat_session(ctx, display_name: str = "sim2real-customer") -> dict:
    session = _start_chat_contact(ctx, display_name)
    _connect_participant(session)
    return session


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
