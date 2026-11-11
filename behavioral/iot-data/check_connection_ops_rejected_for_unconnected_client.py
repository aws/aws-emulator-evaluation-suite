"""connection-ops-rejected-for-unconnected-client."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "connection-ops-rejected-for-unconnected-client"
GROUP = 'connection-management'
SERVICES = ['iot-data']


# `ctx.client("iot-data")` with no endpoint override resolves data-ats.iot.<region>.amazonaws.com,
# which serves every iot-data operation.
_NOT_CONNECTED = (
    "The client ID is not found. Verify that the client is connected and try again"
)


def _error_code(fn):
    """Call fn(); return the botocore Error.Code, or a sentinel if it unexpectedly SUCCEEDS."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code")
    return "<<CALL UNEXPECTEDLY SUCCEEDED>>"


def _error_message(fn):
    """Call fn(); return the botocore Error.Message, or a sentinel if it SUCCEEDS."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Message")
    return "<<CALL UNEXPECTEDLY SUCCEEDED>>"


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """The connection ops read live MQTT session state, so an unconnected client id is a 404.

    GetConnection, ListSubscriptions and SendDirectMessage refuse with the connection message,
    leave no session behind, and the same client still publishes (positive control).
    """
    iot_data = ctx.client("iot-data")
    client_id = ctx.unique_name("sim2real-behav-iotdata-client-")
    topic = f"{ctx.unique_name('sim2real-behav-iotdata-dm-')}/inbox"

    # Each of the three is a distinct URI shape (a GET on the connection, a GET on its
    # subscriptions collection, a POST of a message into it) reaching the same session table.
    probes = [
        ("GetConnection", lambda: iot_data.get_connection(clientId=client_id)),
        ("ListSubscriptions", lambda: iot_data.list_subscriptions(clientId=client_id)),
        ("SendDirectMessage", lambda: iot_data.send_direct_message(
            clientId=client_id, topic=topic, payload=b"sim2real-behav-direct-message")),
    ]
    for name, call in probes:
        code = _error_code(call)
        assert code == "ResourceNotFoundException", (
            f"{name} against a client id that has never connected must be refused with "
            f"ResourceNotFoundException, got {code!r}. An empty-but-successful answer here reads "
            f"to a caller as 'the client exists and is idle'."
        )
        message = _error_message(call)
        assert message == _NOT_CONNECTED, (
            f"{name}'s refusal must name the connection precondition. Expected "
            f"{_NOT_CONNECTED!r}, got {message!r}"
        )

    # Effect absent: the failed SendDirectMessage did not conjure a session, so a follow-up
    # DeleteConnection still finds nothing to disconnect.
    after = _error_code(lambda: iot_data.delete_connection(clientId=client_id))
    assert after == "ResourceNotFoundException", (
        "the refused calls must not have registered a session — DeleteConnection should still "
        f"find no client, got {after!r}"
    )

    # Control, in the same file: the very same client, credentials, region and endpoint publish
    # successfully. So the 404s above are about the absent MQTT session, not about reachability,
    # authorization or a broken data plane.
    published = iot_data.publish(topic=topic, payload=b"sim2real-behav-control-publish", qos=0)
    status = published["ResponseMetadata"]["HTTPStatusCode"]
    assert status == 200, (
        f"control: an ordinary Publish on the same data-plane client must succeed, got {status!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
