"""query-and-json-protocol-clients-share-one-queue."""
from __future__ import annotations

import hashlib
import time
import urllib.parse
import xml.etree.ElementTree as ET

from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.httpsession import URLLib3Session

from behavioral_harness import tags

CHECK = "query-and-json-protocol-clients-share-one-queue"
GROUP = "protocol"
SERVICES = ["sqs"]

_TAGS = {"sim2real": "query-and-json-protocol-clients-share-one-queue"}


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _find_all(root: ET.Element, name: str) -> list[ET.Element]:
    return [e for e in root.iter() if _local(e.tag) == name]


def _text(elem: ET.Element, name: str) -> str | None:
    for child in elem:
        if _local(child.tag) == name:
            return child.text
    return None


def _query_client(ctx, sqs):
    """A signed AWS Query (form-encoded, XML-answering) caller using the ctx client's credentials
    and endpoint."""
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


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:representation", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """Messages and attributes written over the AWS Query protocol read back identically over JSON,
    and vice versa: both wire protocols SQS serves share one queue state.
    """
    sqs = ctx.client("sqs")
    query = _query_client(ctx, sqs)
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-proto-"),
        Attributes={"VisibilityTimeout": "30"},
        tags=_TAGS,
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    # Query -> JSON
    q_body = ctx.unique_name("via-query-")
    status, root = query({
        "Action": "SendMessage", "QueueUrl": url, "MessageBody": q_body,
        "MessageAttribute.1.Name": "proto",
        "MessageAttribute.1.Value.DataType": "String",
        "MessageAttribute.1.Value.StringValue": "query",
    })
    assert status == 200, f"Query SendMessage answered HTTP {status}: {ET.tostring(root)[:300]!r}"
    assert _local(root.tag) == "SendMessageResponse", f"Query answered a {_local(root.tag)!r} root"
    result = _find_all(root, "SendMessageResult")
    assert len(result) == 1, f"Query SendMessage response has {len(result)} SendMessageResult"
    q_id = _text(result[0], "MessageId")
    assert _text(result[0], "MD5OfMessageBody") == hashlib.md5(q_body.encode()).hexdigest(), (
        f"Query MD5OfMessageBody {_text(result[0], 'MD5OfMessageBody')!r} is not the body's MD5"
    )
    q_attr_md5 = _text(result[0], "MD5OfMessageAttributes")

    got = []
    deadline = time.monotonic() + 30
    while not got and time.monotonic() < deadline:
        got = sqs.receive_message(QueueUrl=url, WaitTimeSeconds=3, MaxNumberOfMessages=10,
                                  MessageAttributeNames=["All"]).get("Messages", [])
    assert [m["Body"] for m in got] == [q_body], (
        f"the JSON client received {[m['Body'] for m in got]!r}, expected the Query-sent body"
    )
    m = got[0]
    assert m["MessageId"] == q_id, "the JSON client saw a different MessageId than Query returned"
    assert m["MD5OfMessageAttributes"] == q_attr_md5, (
        f"MD5OfMessageAttributes differs across protocols: JSON {m['MD5OfMessageAttributes']!r}, "
        f"Query {q_attr_md5!r}"
    )
    assert m["MessageAttributes"] == {"proto": {"DataType": "String", "StringValue": "query"}}, (
        f"the Query-sent attribute came back over JSON as {m['MessageAttributes']!r}"
    )
    sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])

    # JSON -> Query
    j_body = ctx.unique_name("via-json-")
    sent = sqs.send_message(QueueUrl=url, MessageBody=j_body, MessageAttributes={
        "proto": {"DataType": "Number", "StringValue": "42"}})
    msgs: list[ET.Element] = []
    deadline = time.monotonic() + 30
    while not msgs and time.monotonic() < deadline:
        status, root = query({
            "Action": "ReceiveMessage", "QueueUrl": url, "MaxNumberOfMessages": "10",
            "WaitTimeSeconds": "3", "MessageAttributeName.1": "All",
        })
        assert status == 200, f"Query ReceiveMessage answered HTTP {status}"
        msgs = _find_all(root, "Message")
    assert len(msgs) == 1, f"Query ReceiveMessage returned {len(msgs)} messages, expected 1"
    qm = msgs[0]
    assert _text(qm, "Body") == j_body, f"Query received body {_text(qm, 'Body')!r}"
    assert _text(qm, "MessageId") == sent["MessageId"], "Query saw a different MessageId"
    assert _text(qm, "MD5OfBody") == sent["MD5OfMessageBody"], "MD5OfBody differs across protocols"
    assert _text(qm, "MD5OfMessageAttributes") == sent["MD5OfMessageAttributes"], (
        "MD5OfMessageAttributes differs across protocols"
    )
    attrs = {_text(a, "Name"): a for a in qm if _local(a.tag) == "MessageAttribute"}
    assert list(attrs) == ["proto"], f"Query received attribute names {list(attrs)!r}"
    value = [v for v in attrs["proto"] if _local(v.tag) == "Value"][0]
    assert (_text(value, "DataType"), _text(value, "StringValue")) == ("Number", "42"), (
        f"the JSON-sent Number attribute came back over Query as "
        f"{(_text(value, 'DataType'), _text(value, 'StringValue'))!r}"
    )
    handle = _text(qm, "ReceiptHandle")
    status, _ = query({"Action": "DeleteMessage", "QueueUrl": url, "ReceiptHandle": handle})
    assert status == 200, f"Query DeleteMessage with a Query-received handle answered {status}"

    # Control plane: a Query write is a JSON read.
    status, _ = query({"Action": "SetQueueAttributes", "QueueUrl": url,
                       "Attribute.1.Name": "VisibilityTimeout", "Attribute.1.Value": "45"})
    assert status == 200, f"Query SetQueueAttributes answered {status}"
    vis = None
    deadline = time.monotonic() + 60
    while vis != "45" and time.monotonic() < deadline:
        vis = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["VisibilityTimeout"])[
            "Attributes"]["VisibilityTimeout"]
        if vis != "45":
            time.sleep(3)
    assert vis == "45", f"a VisibilityTimeout set over Query reads back over JSON as {vis!r}"

    left = sqs.get_queue_attributes(
        QueueUrl=url, AttributeNames=["ApproximateNumberOfMessages",
                                      "ApproximateNumberOfMessagesNotVisible"])["Attributes"]
    deadline = time.monotonic() + 60
    while set(left.values()) != {"0"} and time.monotonic() < deadline:
        time.sleep(3)
        left = sqs.get_queue_attributes(
            QueueUrl=url, AttributeNames=["ApproximateNumberOfMessages",
                                          "ApproximateNumberOfMessagesNotVisible"])["Attributes"]
    assert set(left.values()) == {"0"}, (
        f"both messages were deleted (one per protocol) but the counters read {left!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
