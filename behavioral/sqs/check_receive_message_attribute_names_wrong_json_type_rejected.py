"""receive-message-attribute-names-wrong-json-type-rejected."""
from __future__ import annotations

import json
import time

from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "receive-message-attribute-names-wrong-json-type-rejected"
GROUP = "message-attributes"
SERVICES = ["sqs"]

_SER = "SerializationException"


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:endpoint",
      "plane:data")
def run(ctx) -> None:
    """ReceiveMessage refuses a MessageAttributeNames entry that is a JSON number or a nested
    structure, and refuses the field itself when it is not a JSON array, each with
    SerializationException and an exact message; a well-formed call still returns the message.
    """
    import urllib3

    sqs = ctx.client("sqs")
    endpoint = sqs.meta.endpoint_url
    raw_creds = sqs._request_signer._credentials
    frozen = (raw_creds.get_frozen_credentials()
              if hasattr(raw_creds, "get_frozen_credentials") else raw_creds)
    verify = ctx.http_verify
    pool = urllib3.PoolManager(cert_reqs="CERT_REQUIRED" if verify else "CERT_NONE",
                               ca_certs=verify if isinstance(verify, str) else None)

    def raw(queue_url, message_attribute_names_value):
        """POST ReceiveMessage, SigV4-signed, with the raw value for MessageAttributeNames."""
        data = json.dumps({
            "QueueUrl": queue_url,
            "MessageAttributeNames": message_attribute_names_value,
        }).encode()
        req = AWSRequest(method="POST", url=endpoint, data=data, headers={
            "content-type": "application/x-amz-json-1.0",
            "x-amz-target": "AmazonSQS.ReceiveMessage"})
        SigV4Auth(frozen, "sqs", ctx.region).add_auth(req)
        sent = dict(req.headers.items())
        assert "Authorization" in sent, f"SigV4Auth did not add an Authorization header: {sent!r}"
        resp = pool.request("POST", endpoint, body=data, headers=sent, retries=False)
        body = json.loads(resp.data) if resp.data else {}
        return resp.status, body

    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-sqsrmatype-"))["QueueUrl"]
    ctx.on_cleanup(_teardown(lambda: sqs.delete_queue(QueueUrl=url),
                             "AWS.SimpleQueueService.NonExistentQueue"))

    sent = sqs.send_message(
        QueueUrl=url, MessageBody="payload",
        MessageAttributes={"Color": {"DataType": "String", "StringValue": "blue"}},
    )
    sent_id = sent["MessageId"]

    # ---- the refusal under test: a list entry that is a JSON number or a nested structure.
    matrix = [
        ("a number entry", [5], "NUMBER_VALUE cannot be converted to String"),
        ("a nested structure entry", [{"a": "b"}], "Start of structure or map found where "
                                                     "not expected"),
    ]
    for label, value, expected_message in matrix:
        status, body = raw(url, value)
        assert status == 400, f"MessageAttributeNames={value!r} ({label}) gave {status!r}: {body!r}"
        err_type = body.get("__type", "").rsplit("#", 1)[-1]
        assert err_type == _SER, (
            f"MessageAttributeNames={value!r} ({label}) gave __type {body.get('__type')!r}, "
            f"expected {_SER!r}")
        assert body.get("Message") == expected_message, (
            f"MessageAttributeNames={value!r} ({label}) gave message {body.get('Message')!r}, "
            f"expected {expected_message!r}")
        assert set(body) == {"__type", "Message"}, (
            f"MessageAttributeNames={value!r} ({label}) refusal body carried extra members: "
            f"{body!r}")

    # ---- the field itself sent as something other than a JSON array.
    status, body_scalar = raw(url, 42)
    assert status == 400, f"MessageAttributeNames=42 gave {status!r}: {body_scalar!r}"
    assert body_scalar.get("__type", "").rsplit("#", 1)[-1] == _SER, (
        f"MessageAttributeNames=42 gave __type {body_scalar.get('__type')!r}, expected {_SER!r}")
    assert body_scalar.get("Message") == "Unexpected field type", (
        f"MessageAttributeNames=42 gave message {body_scalar.get('Message')!r}, expected "
        "'Unexpected field type'")
    assert set(body_scalar) == {"__type", "Message"}, (
        f"MessageAttributeNames=42 refusal body carried extra members: {body_scalar!r}")

    # ---- effect-absent: a well-formed poll still returns the one untouched message, unharmed
    #      by the refused calls above.
    deadline = time.monotonic() + 30.0
    msg = None
    while time.monotonic() < deadline and msg is None:
        resp = sqs.receive_message(
            QueueUrl=url, MaxNumberOfMessages=1, WaitTimeSeconds=10,
            MessageAttributeNames=["All"],
        )
        msgs = resp.get("Messages", [])
        if msgs:
            msg = msgs[0]
    assert msg is not None, "a well-formed ReceiveMessage never returned the sent message in 30s"
    assert msg["MessageId"] == sent_id, (
        f"the well-formed receive returned message {msg['MessageId']!r}, expected {sent_id!r}")
    assert msg["MessageAttributes"] == {"Color": {"StringValue": "blue", "DataType": "String"}}, (
        f"the well-formed receive returned attributes {msg.get('MessageAttributes')!r}")
    sqs.delete_message(QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"])


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
