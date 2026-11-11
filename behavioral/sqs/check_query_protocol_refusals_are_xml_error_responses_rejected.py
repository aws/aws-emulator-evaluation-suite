"""query-protocol-refusals-are-xml-error-responses-rejected."""
from __future__ import annotations

import time
import urllib.parse
import xml.etree.ElementTree as ET

from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.exceptions import ClientError
from botocore.httpsession import URLLib3Session

from behavioral_harness import tags

CHECK = "query-protocol-refusals-are-xml-error-responses-rejected"
GROUP = "protocol"
SERVICES = ["sqs"]

_TAGS = {"sim2real": "query-protocol-refusals-are-xml-error-responses-rejected"}
_NO_SUCH_QUEUE = "AWS.SimpleQueueService.NonExistentQueue"
_DELAY_MSG = "Value 901 for parameter DelaySeconds is invalid. Reason: DelaySeconds must be >= 0 and <= 900."


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _query_client(ctx, sqs):
    """A signer for the AWS Query protocol using the ctx client's credentials and endpoint."""
    raw_creds = sqs._request_signer._credentials
    frozen = (raw_creds.get_frozen_credentials()
              if hasattr(raw_creds, "get_frozen_credentials") else raw_creds)
    endpoint = sqs.meta.endpoint_url
    http = URLLib3Session(verify=ctx.http_verify)

    def call(params: dict[str, str]) -> tuple[int, ET.Element]:
        body = urllib.parse.urlencode({**params, "Version": "2012-11-05"})
        req = AWSRequest(method="POST", url=endpoint + "/", data=body, headers={
            "Content-Type": "application/x-www-form-urlencoded; charset=utf-8"})
        SigV4Auth(frozen, sqs.meta.service_model.signing_name, ctx.region).add_auth(req)
        resp = http.send(req.prepare())
        return resp.status_code, ET.fromstring(resp.content)

    return call


def _query_error(status: int, root: ET.Element) -> tuple[int, str, str | None, str | None, str | None]:
    """(status, root element, Error/Type, Error/Code, Error/Message) of a Query response."""
    error = [e for e in root if _local(e.tag) == "Error"]
    fields: dict[str, str | None] = {}
    if error:
        fields = {_local(c.tag): c.text for c in error[0]}
    return (status, _local(root.tag), fields.get("Type"), fields.get("Code"), fields.get("Message"))


def _json_error(fn) -> dict:
    """The botocore Error dict ``fn`` raises. An unexpected success raises, naming the result."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """Over the AWS Query protocol SQS refuses with an XML ErrorResponse (Type, Code, Message) for an
    absent queue, DelaySeconds 901, an 11-entry batch and an unknown Action; the absent-queue message
    is Query-specific ("... for this wsdl version."), and only the valid send is enqueued.
    """
    sqs = ctx.client("sqs")
    query = _query_client(ctx, sqs)
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-qerr-"), tags=_TAGS)[
        "QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    absent = ctx.unique_name("sim2real-behav-qerr-absent-")

    got = _query_error(*query({"Action": "GetQueueUrl", "QueueName": absent}))
    assert got == (400, "ErrorResponse", "Sender", _NO_SUCH_QUEUE,
                   "The specified queue does not exist for this wsdl version."), (
        f"Query GetQueueUrl for an absent queue answered {got!r}"
    )
    j = _json_error(lambda: sqs.get_queue_url(QueueName=absent))
    assert (j.get("Code"), j.get("Message")) == (_NO_SUCH_QUEUE, "The specified queue does not exist."), (
        f"JSON GetQueueUrl for the same absent queue answered {j!r}"
    )

    got = _query_error(*query({"Action": "SendMessage", "QueueUrl": url,
                               "MessageBody": "too-late", "DelaySeconds": "901"}))
    assert got == (400, "ErrorResponse", "Sender", "InvalidParameterValue", _DELAY_MSG), (
        f"Query SendMessage with DelaySeconds 901 answered {got!r}"
    )
    j = _json_error(lambda: sqs.send_message(QueueUrl=url, MessageBody="too-late", DelaySeconds=901))
    assert (j.get("Code"), j.get("Message")) == ("InvalidParameterValue", _DELAY_MSG), (
        f"JSON SendMessage with DelaySeconds 901 answered {j!r}"
    )

    entries = {}
    for k in range(1, 12):
        entries[f"DeleteMessageBatchRequestEntry.{k}.Id"] = f"i{k}"
        entries[f"DeleteMessageBatchRequestEntry.{k}.ReceiptHandle"] = "not-a-handle"
    got = _query_error(*query({"Action": "DeleteMessageBatch", "QueueUrl": url, **entries}))
    assert got == (400, "ErrorResponse", "Sender",
                   "AWS.SimpleQueueService.TooManyEntriesInBatchRequest",
                   "Maximum number of entries per request are 10. You have sent 11."), (
        f"Query DeleteMessageBatch with 11 entries answered {got!r}"
    )

    got = _query_error(*query({"Action": "NoSuchAction", "QueueUrl": url}))
    assert got == (400, "ErrorResponse", "Sender", "InvalidAction",
                   "The action NoSuchAction is not valid for this endpoint."), (
        f"Query with an unknown Action answered {got!r}"
    )

    # Positive control: a valid Query send on the same queue is accepted, and it is the only
    # message the queue holds.
    ok_body = ctx.unique_name("ok-")
    status, root = query({"Action": "SendMessage", "QueueUrl": url, "MessageBody": ok_body})
    assert (status, _local(root.tag)) == (200, "SendMessageResponse"), (
        f"a valid Query SendMessage answered {status} {_local(root.tag)!r}"
    )
    bodies: list[str] = []
    deadline = time.monotonic() + 30
    while ok_body not in bodies and time.monotonic() < deadline:
        for m in sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10,
                                     WaitTimeSeconds=3).get("Messages", []):
            bodies.append(m["Body"])
            sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])
    bodies.extend(m["Body"] for m in sqs.receive_message(
        QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=2).get("Messages", []))
    assert bodies == [ok_body], (
        f"the queue delivered {bodies!r}; expected only the valid Query-sent message"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
