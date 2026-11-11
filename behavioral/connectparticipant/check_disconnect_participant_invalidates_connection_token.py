"""disconnect-participant-invalidates-connection-token."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "disconnect-participant-invalidates-connection-token"
GROUP = "state-transitions"
SERVICES = ["connectparticipant"]
# Cost: nothing here is optional on any backend. A run creates one Connect instance and
# deletes it in its teardown.


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """DisconnectParticipant transitions the participant from CONNECTED to DISCONNECTED;
    every subsequent call on that ConnectionToken is rejected, while a fresh, independent
    chat session's connection continues to work normally (positive control)."""
    session = _setup_chat_session(ctx)
    cp = session["cp"]

    pre = cp.send_message(
        ContentType="text/plain", Content="pre-disconnect", ConnectionToken=session["connection_token"]
    )
    assert pre["Id"], f"expected pre-disconnect send_message to return an Id, got {pre!r}"

    cp.disconnect_participant(ConnectionToken=session["connection_token"])

    write_err = _error(
        lambda: cp.send_message(
            ContentType="text/plain", Content="post-disconnect", ConnectionToken=session["connection_token"]
        )
    )
    assert write_err == ("AccessDeniedException", "Access denied"), (
        f"expected AccessDeniedException 'Access denied' writing with a disconnected token, got {write_err!r}"
    )

    # independent read, not just another write attempt: the connection token must be dead for
    # reads too, not merely rejected for the specific mutation we broke.
    read_err = _error(lambda: cp.get_transcript(ConnectionToken=session["connection_token"]))
    assert read_err == ("AccessDeniedException", "Access denied"), (
        f"expected AccessDeniedException 'Access denied' reading a transcript with a disconnected token, "
        f"got {read_err!r}"
    )

    # positive control: an independent session is unaffected by the first one's disconnect
    control = _setup_chat_session(ctx)
    control_resp = control["cp"].send_message(
        ContentType="text/plain", Content="control-message", ConnectionToken=control["connection_token"]
    )
    assert control_resp["Id"], f"expected the independent control session to keep working, got {control_resp!r}"


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _error(fn):
    """(code, message) of the ClientError ``fn`` raises; an unexpected success fails the check."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


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
            time.sleep(2)
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
        time.sleep(2)


def _create_instance(ctx, connect) -> str:
    """A new, ACTIVE Connect instance whose teardown is registered before anything can fail."""
    instance_id = connect.create_instance(
        IdentityManagementType="CONNECT_MANAGED",
        InstanceAlias=ctx.unique_name(_CP_ALIAS_PREFIX).lower()[:45],
        InboundCallsEnabled=True,
        OutboundCallsEnabled=True,
    )["Id"]
    ctx.on_cleanup(lambda: _delete_instance(connect, instance_id))
    left = ctx.time_left()
    status = _poll_until(
        lambda: connect.describe_instance(InstanceId=instance_id)["Instance"]["InstanceStatus"],
        lambda status: status != "CREATION_IN_PROGRESS",
        timeout_s=300.0 if left is None else min(300.0, max(1.0, left - 30.0)),
        interval_s=2,
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
