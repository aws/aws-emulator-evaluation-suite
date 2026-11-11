"""aws-proxy-subtype-sqs-receivemessage-required-queueurl-refused-else-reads-the-queue."""

from __future__ import annotations

import json
import ssl
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET

from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "aws-proxy-subtype-sqs-receivemessage-required-queueurl-refused-else-reads-the-queue"

GROUP = "integrations"

SERVICES = ["apigatewayv2", "sqs"]

_SQS_QUERY_XMLNS = "http://queue.amazonaws.com/doc/2012-11-05/"


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:data-plane",
    "concern:eventing",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:control",
    "plane:data",
)
def run(ctx) -> None:
    """CreateIntegration refuses an SQS-ReceiveMessage subtype integration missing the required
    QueueUrl parameter, and the same subtype with QueueUrl mapped returns the queue's own message
    unchanged through the invoke URL.

    Reference: https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-develop-integrations-aws-services-reference.html
    """
    marker = ctx.unique_name("sim2real-xsvc-sqsrecv-")
    sqs = ctx.client("sqs")
    queue_url = sqs.create_queue(
        QueueName=_xname(ctx, "recvq"), tags=_xsvc_resource_tags()
    )["QueueUrl"]
    ctx.on_cleanup(lambda: ctx.client("sqs").delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]

    credentials_arn = _create_role(
        ctx,
        "apigateway.amazonaws.com",
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": ["sqs:ReceiveMessage"], "Resource": queue_arn}
            ],
        },
    )

    agw = ctx.client("apigatewayv2")
    api = agw.create_api(
        Name=_xname(ctx, "httpapi-sqsrecv"), ProtocolType="HTTP", Tags=_xsvc_resource_tags()
    )
    api_id = api["ApiId"]
    ctx.on_cleanup(lambda: ctx.client("apigatewayv2").delete_api(ApiId=api_id))

    # --- the required-parameter refusal: QueueUrl is the only required field, and it is absent.
    code, message = _error(
        lambda: agw.create_integration(
            ApiId=api_id,
            IntegrationType="AWS_PROXY",
            IntegrationSubtype="SQS-ReceiveMessage",
            PayloadFormatVersion="1.0",
            CredentialsArn=credentials_arn,
            RequestParameters={},
        )
    )
    assert code == "BadRequestException", f"expected BadRequestException, got {code}: {message!r}"
    assert message == (
        "Operation: SQS-ReceiveMessage requires enabling passthrough, or defining all of the "
        "following parameters in the parameter mapping: [QueueUrl]"
    ), f"unexpected message {message!r}"

    # --- the positive control: QueueUrl mapped, the integration created and reachable.
    integration_id = agw.create_integration(
        ApiId=api_id,
        IntegrationType="AWS_PROXY",
        IntegrationSubtype="SQS-ReceiveMessage",
        PayloadFormatVersion="1.0",
        CredentialsArn=credentials_arn,
        RequestParameters={"QueueUrl": queue_url},
    )["IntegrationId"]
    # The route returns queue data, so only a SigV4-signed caller of this account reaches it.
    agw.create_route(
        ApiId=api_id,
        RouteKey="GET /recv",
        Target=f"integrations/{integration_id}",
        AuthorizationType="AWS_IAM",
    )
    agw.create_stage(
        ApiId=api_id, StageName="$default", AutoDeploy=True, Tags=_xsvc_resource_tags()
    )
    ctx.on_cleanup(
        lambda: ctx.client("apigatewayv2").delete_stage(ApiId=api_id, StageName="$default")
    )

    stored = agw.get_integration(ApiId=api_id, IntegrationId=integration_id)
    assert stored.get("RequestParameters", {}).get("QueueUrl") == queue_url, (
        f"the QueueUrl mapping must be stored as authored, got "
        f"{stored.get('RequestParameters', {}).get('QueueUrl')!r}"
    )

    sent = sqs.send_message(QueueUrl=queue_url, MessageBody=marker)
    url = f"{ctx.stage_url(api['ApiEndpoint'], '$default')}/recv"
    status, text, received = _poll_until_message(ctx, url, timeout_s=90.0)
    assert status == 200, f"expected 200 from the SQS-ReceiveMessage subtype, got {status}: {text[:300]!r}"
    assert received is not None, f"expected a parseable ReceiveMessageResponse, got {text[:300]!r}"
    assert received["body"] == marker, (
        f"the message body returned through the gateway must be the queue's own body {marker!r}, "
        f"got {received['body']!r}"
    )
    assert received["message_id"] == sent["MessageId"], (
        f"the MessageId returned through the gateway must be the one SendMessage minted "
        f"({sent['MessageId']!r}), got {received['message_id']!r}"
    )
    sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=received["receipt_handle"])


def _xsvc_resource_tags() -> dict:
    return {"sim2real:managed": "true", "sim2real:prefix": "sim2real-xsvc"}


def _xname(ctx, kind: str) -> str:
    return ctx.unique_name(f"sim2real-xsvc-{kind}-")


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _extract_message(text: str):
    """The AWS_PROXY-to-SQS response is SQS's own classic query-protocol XML
    (ReceiveMessageResponse), passed through verbatim."""
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return None
    message = root.find(f".//{{{_SQS_QUERY_XMLNS}}}Message")
    if message is None:
        return None
    return {
        "message_id": message.findtext(f"{{{_SQS_QUERY_XMLNS}}}MessageId"),
        "receipt_handle": message.findtext(f"{{{_SQS_QUERY_XMLNS}}}ReceiptHandle"),
        "body": message.findtext(f"{{{_SQS_QUERY_XMLNS}}}Body"),
    }


def _poll_until_message(ctx, url, *, timeout_s, interval_s=3.0):
    """Signed GETs to a SQS-ReceiveMessage route until a 200 carries a parsed ``<Message>``.

    A 200 with an empty ``ReceiveMessageResult`` is a legitimate miss (SQS's own distributed
    polling), not a failure; keep polling until the deadline. Returns (status, text, message).
    """
    budget = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + budget
    while True:
        last_status, _, last_text = _signed_http(ctx, "GET", url)
        if last_status == 200:
            message = _extract_message(last_text)
            if message is not None:
                return last_status, last_text, message
        if time.monotonic() >= deadline:
            break
        time.sleep(interval_s)
    raise TimeoutError(
        f"{url} never returned a message within {budget:.0f}s. Last: {last_status} "
        f"{last_text[:300]!r}"
    )


def _budget_s(ctx, want_s):
    """``want_s`` capped by the time the runner leaves this check."""
    left = ctx.time_left()
    return want_s if left is None else max(1.0, min(want_s, left - 10.0))


def _ssl_context(verify):
    """An SSLContext honouring ``ctx.http_verify``: True, False, or a CA bundle path."""
    if verify is False:
        return ssl._create_unverified_context()
    return ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)


def _signed_http(ctx, method, url, body=None, headers=None, timeout_s=20):
    """(status, headers, text) of one SigV4-signed request; status None on a transport error."""
    creds = ctx.client("sts")._request_signer._credentials.get_frozen_credentials()
    req = AWSRequest(method=method, url=url, data=body, headers=headers or {})
    SigV4Auth(creds, "execute-api", ctx.region).add_auth(req)
    raw = urllib.request.Request(url, data=body, method=method, headers=dict(req.headers))
    try:
        with urllib.request.urlopen(
            raw, timeout=timeout_s, context=_ssl_context(ctx.http_verify)
        ) as resp:
            return resp.status, dict(resp.getheaders()), resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers.items()), exc.read().decode("utf-8", "replace")
    except OSError as exc:
        return None, {}, f"connection error: {exc}"


def _delete_role(ctx, role_name):
    iam = ctx.client("iam")
    try:
        for p in iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", []):
            iam.detach_role_policy(RoleName=role_name, PolicyArn=p["PolicyArn"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_role(ctx, trust_service, inline_policy=None):
    iam = ctx.client("iam")
    role_name = _xname(ctx, f"role-{trust_service.split('.')[0]}")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": trust_service},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Path="/sim2real/",
        Tags=[{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()],
    )
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    if inline_policy:
        iam.put_role_policy(
            RoleName=role_name, PolicyName="inline", PolicyDocument=json.dumps(inline_policy)
        )
    return resp["Role"]["Arn"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
