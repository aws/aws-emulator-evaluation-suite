"""aws-proxy-subtype-sqs-purgequeue-required-queueurl-refused-else-empties-the-queue."""

from __future__ import annotations

import json
import ssl
import time
import urllib.error
import urllib.request

from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "aws-proxy-subtype-sqs-purgequeue-required-queueurl-refused-else-empties-the-queue"

GROUP = "integrations"

SERVICES = ["apigatewayv2", "sqs"]


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
    """CreateIntegration refuses an SQS-PurgeQueue subtype integration missing the required
    QueueUrl parameter, and the same subtype with QueueUrl mapped empties a queue that held
    several messages.

    Reference: https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-develop-integrations-aws-services-reference.html
    """
    sqs = ctx.client("sqs")
    queue_url = sqs.create_queue(
        QueueName=_xname(ctx, "purgeq"), tags=_xsvc_resource_tags()
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
                {"Effect": "Allow", "Action": ["sqs:PurgeQueue"], "Resource": queue_arn}
            ],
        },
    )

    agw = ctx.client("apigatewayv2")
    api = agw.create_api(
        Name=_xname(ctx, "httpapi-sqspurge"), ProtocolType="HTTP", Tags=_xsvc_resource_tags()
    )
    api_id = api["ApiId"]
    ctx.on_cleanup(lambda: ctx.client("apigatewayv2").delete_api(ApiId=api_id))

    # --- the required-parameter refusal: QueueUrl is the only required field, and it is absent.
    code, message = _error(
        lambda: agw.create_integration(
            ApiId=api_id,
            IntegrationType="AWS_PROXY",
            IntegrationSubtype="SQS-PurgeQueue",
            PayloadFormatVersion="1.0",
            CredentialsArn=credentials_arn,
            RequestParameters={},
        )
    )
    assert code == "BadRequestException", f"expected BadRequestException, got {code}: {message!r}"
    assert message == (
        "Operation: SQS-PurgeQueue requires enabling passthrough, or defining all of the "
        "following parameters in the parameter mapping: [QueueUrl]"
    ), f"unexpected message {message!r}"

    # --- the positive control: QueueUrl mapped, a non-empty queue emptied by one invocation.
    integration_id = agw.create_integration(
        ApiId=api_id,
        IntegrationType="AWS_PROXY",
        IntegrationSubtype="SQS-PurgeQueue",
        PayloadFormatVersion="1.0",
        CredentialsArn=credentials_arn,
        RequestParameters={"QueueUrl": queue_url},
    )["IntegrationId"]
    # The route empties the queue, so only a SigV4-signed caller of this account reaches it.
    agw.create_route(
        ApiId=api_id,
        RouteKey="GET /purge",
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

    for i in range(3):
        sqs.send_message(QueueUrl=queue_url, MessageBody=f"sim2real-purge-{i}")
    _poll_until(
        ctx,
        lambda: int(
            sqs.get_queue_attributes(
                QueueUrl=queue_url, AttributeNames=["ApproximateNumberOfMessages"]
            )["Attributes"]["ApproximateNumberOfMessages"]
        ),
        lambda d: d >= 3,
        timeout_s=30.0,
        interval_s=2.0,
        description="the queue reporting the 3 sent messages before purging",
    )

    url = f"{ctx.stage_url(api['ApiEndpoint'], '$default')}/purge"
    status, _, text = _poll_http(
        ctx,
        url, accept=lambda s: s == 200, description="GET /purge reaching the SQS-PurgeQueue integration"
    )
    assert status == 200, f"expected 200 from the SQS-PurgeQueue subtype, got {status}: {text[:300]!r}"

    after = _poll_until(
        ctx,
        lambda: int(
            sqs.get_queue_attributes(
                QueueUrl=queue_url, AttributeNames=["ApproximateNumberOfMessages"]
            )["Attributes"]["ApproximateNumberOfMessages"]
        ),
        lambda d: d == 0,
        # PurgeQueue takes up to 60 seconds, and the approximate depth lags behind it.
        timeout_s=150.0,
        interval_s=2.0,
        description="the queue depth reaching 0 after the mapped PurgeQueue",
    )
    assert after == 0, f"expected ApproximateNumberOfMessages == 0 after purge, got {after}"


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


def _poll_http(ctx, url, *, accept, method="GET", body=None, headers=None, timeout_s=90.0,
               interval_s=3.0, description="invoke URL"):
    """Signed requests to ``url`` until ``accept(status)``; TimeoutError with the last answer."""
    budget = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + budget
    while True:
        last = _signed_http(ctx, method, url, body=body, headers=headers)
        if accept(last[0]):
            return last
        if time.monotonic() >= deadline:
            break
        time.sleep(interval_s)
    raise TimeoutError(
        f"{description} ({url}) never reached an accepted status within {budget:.0f}s. "
        f"Last: {last[0]} {last[2][:300]!r}"
    )


def _poll_until(ctx, probe, predicate, *, timeout_s=60.0, interval_s=2.0, description="condition"):
    budget = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + budget
    last = None
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            break
        time.sleep(interval_s)
    raise TimeoutError(f"{description} not met within {budget:.0f}s. Last result: {last!r}")


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
