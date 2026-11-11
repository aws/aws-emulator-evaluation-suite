"""raw-json-post-missing-target-or-mismatched-content-type-rejected."""
from __future__ import annotations

import json
import re

import urllib3
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest

from behavioral_harness import tags

CHECK = "raw-json-post-missing-target-or-mismatched-content-type-rejected"
GROUP = "error-semantics"
SERVICES = ["sqs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A signed CreateQueue POST with no X-Amz-Target, and one with Content-Type
    application/json instead of application/x-amz-json-1.0, are both refused as an
    unknown operation and create no queue; a request carrying both headers succeeds.

    Reference: https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-making-api-requests-json.html
    """
    sqs = ctx.client("sqs")
    target_name = ctx.unique_name("sim2real-behav-rawpost-")
    body = json.dumps({"QueueName": target_name}).encode("utf-8")

    status_a, text_a = _raw_post(ctx, body, content_type="application/x-amz-json-1.0", target=None)
    assert status_a == 400, f"missing X-Amz-Target gave status {status_a}, body {text_a!r}"
    payload_a = json.loads(text_a)
    assert payload_a == {"__type": "com.amazon.coral.service#UnknownOperationException"}, (
        f"missing X-Amz-Target gave body {payload_a!r}"
    )

    status_b, text_b = _raw_post(ctx, body, content_type="application/json", target="AmazonSQS.CreateQueue")
    assert status_b == 404, f"Content-Type application/json gave status {status_b}, body {text_b!r}"
    assert text_b == "<UnknownOperationException/>\n", f"Content-Type application/json gave body {text_b!r}"

    assert _code_of(status_a, payload_a) == _code_of(status_b, text_b) == "UnknownOperationException"

    not_created = _error_code(lambda: sqs.get_queue_url(QueueName=target_name))
    assert not_created == "AWS.SimpleQueueService.NonExistentQueue", (
        f"a queue named after the rejected requests' body exists: {not_created!r}"
    )

    control_name = ctx.unique_name("sim2real-behav-rawpost-")
    control_body = json.dumps({"QueueName": control_name}).encode("utf-8")
    status_ok, text_ok = _raw_post(
        ctx, control_body, content_type="application/x-amz-json-1.0", target="AmazonSQS.CreateQueue"
    )
    assert status_ok == 200, f"a correctly-headered CreateQueue gave status {status_ok}, body {text_ok!r}"
    control_url = json.loads(text_ok)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=control_url))
    assert sqs.get_queue_url(QueueName=control_name)["QueueUrl"] == control_url


def _code_of(status, body):
    if isinstance(body, dict):
        return body["__type"].split("#")[-1]
    match = re.fullmatch(r"<(\w+)/>\n", body)
    return match.group(1)


def _error_code(fn) -> str:
    """The Error.Code ``fn`` raises. An unexpected success raises too, naming what came back."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"]
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _raw_post(ctx, body: bytes, *, content_type: str, target: str | None):
    client = ctx.client("sqs")
    endpoint = client.meta.endpoint_url
    signing_name = client.meta.service_model.signing_name
    creds = client._request_signer._credentials
    frozen = creds.get_frozen_credentials() if hasattr(creds, "get_frozen_credentials") else creds
    headers = {"Content-Type": content_type}
    if target is not None:
        headers["X-Amz-Target"] = target
    request = AWSRequest(method="POST", url=endpoint, data=body, headers=headers)
    SigV4Auth(frozen, signing_name, ctx.region).add_auth(request)
    prepared = request.prepare()
    http = urllib3.PoolManager()
    resp = http.request(
        prepared.method, prepared.url, body=prepared.body, headers=dict(prepared.headers),
        timeout=15,
    )
    return resp.status, resp.data.decode("utf-8")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
