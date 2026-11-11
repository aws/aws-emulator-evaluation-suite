"""create-participant-connection-rejected-inputs."""
from __future__ import annotations

import json
import time
import uuid

from botocore.config import Config

from behavioral_harness import tags


CHECK = "create-participant-connection-rejected-inputs"
GROUP = "overly-permissive"
SERVICES = ["connectparticipant"]
# Cost: nothing here is optional on any backend. A run creates one Connect instance and
# deletes it in its teardown.


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateParticipantConnection rejects an empty Type list and a bogus ParticipantToken with distinct
    codes, while the real ParticipantToken still connects and its ConnectionToken sends and reads back a
    message (client-side validation is off for the empty-list call so the service's own error is graded)."""
    session = _start_chat_contact(ctx)
    cp = session["cp"]
    unvalidated_cp = ctx.client("connectparticipant", config=Config(parameter_validation=False))

    empty_type_err = _error(
        lambda: unvalidated_cp.create_participant_connection(
            ParticipantToken=session["participant_token"], Type=[]
        )
    )
    assert empty_type_err == (
        "ValidationException",
        "Failed to create participant connection due to missing connection type",
    ), f"got {empty_type_err!r}"

    bogus_token = "bogus-participant-token-" + str(uuid.uuid4())
    bogus_token_err = _error(
        lambda: cp.create_participant_connection(ParticipantToken=bogus_token, Type=["CONNECTION_CREDENTIALS"])
    )
    # AWS answers a ParticipantToken it never issued with this fixed text.
    assert bogus_token_err == (
        "AccessDeniedException",
        "User is not authorized to access this resource with an explicit deny in an identity-based policy",
    ), f"got {bogus_token_err!r}"

    # positive control: the genuine token still works
    resp = cp.create_participant_connection(
        ParticipantToken=session["participant_token"], Type=["CONNECTION_CREDENTIALS"]
    )
    connection_token = resp["ConnectionCredentials"]["ConnectionToken"]
    assert connection_token

    # independent proof the minted token is live: use it for a real call (SendMessage) and read
    # the effect back through a different operation (GetTranscript) at the destination, rather
    # than trusting that a non-empty string in the create response means a working credential.
    body = f"sim2real-hello-{ctx.unique_name('')}"
    sent = cp.send_message(ContentType="text/plain", Content=body, ConnectionToken=connection_token)
    msg_id = sent["Id"]
    items = _poll_until(
        lambda: cp.get_transcript(ConnectionToken=connection_token, MaxResults=50)["Transcript"],
        lambda items: any(i["Id"] == msg_id for i in items),
        timeout_s=30,
        interval_s=2,
    )
    item = next(i for i in items if i["Id"] == msg_id)
    assert item["Content"] == body, f"got {item['Content']!r}"
    assert item["Type"] == "MESSAGE", f"got {item['Type']!r}"


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
