"""esm-event-source-arn-type-and-account-rejected."""

from __future__ import annotations

import json
import textwrap
import time
import zipfile
from io import BytesIO
from urllib.parse import urlsplit

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "esm-event-source-arn-type-and-account-rejected"
GROUP = "arn-resolution"
SERVICES = ["lambda", "s3", "sqs"]


_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"


def _xsvc_resource_tags():
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv():
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx, kind):
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _expect_error(fn):
    """Call fn(); return the botocore Error (Code, Message) if a ClientError is raised.

    An unexpected SUCCESS raises, because an emulator ACCEPTING input real AWS refuses is the
    strongest signal available.
    """
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


def _retry_client_error(fn, *, codes, timeout_s=120.0, interval_s=3.0, description="call"):
    """Call fn() until it stops raising one of `codes`, with a bounded deadline.

    IAM propagation is real and slow: a resource policy naming a just-created role is rejected
    ("invalid principal") until IAM converges, and a service that must assume a brand-new role
    reports it cannot. This retries that window instead of sleeping blind — the deadline is the
    assertion, never a bare time.sleep.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in codes or time.monotonic() >= deadline:
                raise AssertionError(
                    f"{description} still failing with {code} after {timeout_s}s"
                ) from exc
        time.sleep(interval_s)


def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


def _create_role(ctx, trust, inline_policy=None, kind=None):
    """Create an IAM role and register its (policies-then-role) teardown. Returns {name, arn}.

    `trust` is either a service principal string ("lambda.amazonaws.com") or a full trust-policy
    document, which is what the role-to-role AssumeRole checks need.
    """
    iam = ctx.client("iam")
    if isinstance(trust, str):
        doc = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": trust},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
        kind = kind or f"role-{trust.split('.')[0]}"
    else:
        doc = trust
        kind = kind or "role"
    role_name = _xname(ctx, kind)
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(doc),
        Path="/sim2real/",
        Tags=_xsvc_tags_kv(),
    )
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    if inline_policy:
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName="inline",
            PolicyDocument=json.dumps(inline_policy),
        )
    return {"name": role_name, "arn": resp["Role"]["Arn"]}


def _delete_role(ctx, role_name):
    """IAM roles need every attached + inline policy removed before deletion."""
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


def _wait_function_active(ctx, name, timeout_s=90.0):
    lam = ctx.client("lambda")
    _poll_until(
        lambda: lam.get_function_configuration(FunctionName=name),
        lambda r: r.get("State") == "Active",
        timeout_s=timeout_s,
        interval_s=2.0,
        description=f"Lambda {name} active",
    )


def _create_function_with_retry(ctx, handler_code, role_arn, env=None, timeout=30, memory=128,
                                runtime="python3.12"):
    """Create a Lambda, retrying through the IAM role-propagation window, then wait until Active.

    Registers the function + its auto-created log group for teardown. The inline handler source is
    dedented and aliased to the fixed `lambda_function.lambda_handler` entrypoint.
    """
    name = _xname(ctx, "fn")
    lam = ctx.client("lambda")
    handler_code = textwrap.dedent(handler_code)
    if "def lambda_handler" not in handler_code and "def handler" in handler_code:
        handler_code = handler_code.rstrip() + "\n\nlambda_handler = handler\n"
    zip_buf = BytesIO()
    with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", handler_code)
    kwargs = {
        "FunctionName": name,
        "Runtime": runtime,
        "Role": role_arn,
        "Handler": "lambda_function.lambda_handler",
        "Code": {"ZipFile": zip_buf.getvalue()},
        "Timeout": timeout,
        "MemorySize": memory,
        "Tags": dict(_xsvc_resource_tags()),
    }
    if env:
        kwargs["Environment"] = {"Variables": env}
    deadline = time.monotonic() + 60
    last_err = None
    while time.monotonic() < deadline:
        try:
            resp = lam.create_function(**kwargs)
            ctx.on_cleanup(lambda: ctx.client("lambda").delete_function(FunctionName=name))
            ctx.on_cleanup(lambda: _delete_log_group_if_present(ctx, f"/aws/lambda/{name}"))
            _wait_function_active(ctx, name)
            return {"name": name, "arn": resp["FunctionArn"]}
        except ClientError as e:
            if "cannot be assumed" in str(e) or "InvalidParameterValue" in str(e):
                last_err = e
                time.sleep(3)
                continue
            raise
    raise last_err or RuntimeError(f"Failed to create Lambda {name}")


def _delete_log_group_if_present(ctx, log_group_name):
    """A function that was never invoked has no log group; that is already clean."""
    try:
        ctx.client("logs").delete_log_group(logGroupName=log_group_name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _create_lambda(ctx, handler_code, permissions=None, env=None, timeout=30, memory=128,
                   runtime="python3.12"):
    """Create a Lambda whose execution role is scoped to `permissions` (IAM statement fragments
    like [{"Action": ["kms:Decrypt"], "Resource": key_arn}]); logs are always allowed.

    Returns {name, arn, role_name, role_arn} — the role identifiers matter here because these
    checks name the execution role as the *principal* in another service's resource policy.
    """
    statements = [
        {
            "Effect": "Allow",
            "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
            "Resource": "arn:aws:logs:*:*:*",
        }
    ]
    for perm in permissions or []:
        actions = perm["Action"] if isinstance(perm["Action"], list) else [perm["Action"]]
        resource = perm["Resource"] if isinstance(perm["Resource"], list) else [perm["Resource"]]
        stmt = {"Effect": perm.get("Effect", "Allow"), "Action": actions, "Resource": resource}
        if perm.get("Condition"):
            stmt["Condition"] = perm["Condition"]
        statements.append(stmt)
    role = _create_role(
        ctx,
        "lambda.amazonaws.com",
        inline_policy={"Version": "2012-10-17", "Statement": statements},
    )
    fn = _create_function_with_retry(ctx, handler_code, role["arn"], env, timeout, memory, runtime)
    return {**fn, "role_name": role["name"], "role_arn": role["arn"]}


def _invoke_lambda(ctx, name, payload=None):
    """Invoke a Lambda synchronously; return {status_code[, error], payload|payload_raw}."""
    resp = ctx.client("lambda").invoke(
        FunctionName=name,
        InvocationType="RequestResponse",
        Payload=json.dumps(payload or {}).encode(),
    )
    body = resp["Payload"].read()
    result = {"status_code": resp["StatusCode"]}
    if resp.get("FunctionError"):
        result["error"] = resp["FunctionError"]
    try:
        result["payload"] = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        result["payload_raw"] = body.decode("utf-8", errors="replace")
    return result


def _invoke_payload(ctx, name, payload=None):
    """Invoke and return the parsed RESULT PAYLOAD, asserting the handler did not fault.

    A 200 from Invoke proves nothing about the cross-service reference; the payload the handler
    produced after touching the other service is the evidence.
    """
    result = _invoke_lambda(ctx, name, payload)
    assert result.get("status_code") == 200, f"Invoke did not return 200: {result!r}"
    assert "error" not in result, f"handler faulted instead of returning a result: {result!r}"
    assert "payload" in result, f"handler returned non-JSON: {result!r}"
    return result["payload"]


def _delete_bucket(s3, bucket):
    """Empty a bucket (objects + versions + delete markers) then delete it; best-effort teardown."""
    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
            for o in page.get("Versions", []) + page.get("DeleteMarkers", []):
                s3.delete_object(Bucket=bucket, Key=o["Key"], VersionId=o["VersionId"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            for o in page.get("Contents", []):
                s3.delete_object(Bucket=bucket, Key=o["Key"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _new_bucket(ctx, kind="bkt"):
    """Create a uniquely-named, region-correct bucket; register empty+delete teardown."""
    s3 = ctx.client("s3")
    name = _xname(ctx, kind)
    params = {"Bucket": name}
    if ctx.region and ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(ctx.client("s3"), name))
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": _xsvc_tags_kv()})
    return name


def _create_queue(ctx, kind="q"):
    """Create a queue; register teardown. Returns {name, url, arn}."""
    sqs = ctx.client("sqs")
    name = _xname(ctx, kind)
    url = sqs.create_queue(QueueName=name, tags=dict(_xsvc_resource_tags()))["QueueUrl"]
    ctx.on_cleanup(lambda: ctx.client("sqs").delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]
    return {"name": name, "url": url, "arn": arn}


def _queue_depth(ctx, url):
    """Visible + in-flight message count — the observable for 'nothing consumed it'."""
    attrs = ctx.client("sqs").get_queue_attributes(
        QueueUrl=url,
        AttributeNames=["ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible"],
    )["Attributes"]
    return int(attrs["ApproximateNumberOfMessages"]) + int(
        attrs["ApproximateNumberOfMessagesNotVisible"]
    )


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "concern:negative-classes", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """CreateEventSourceMapping rejects an S3 bucket ARN, a foreign-account queue ARN and a malformed
    ARN, each with its exact error, and creates no mapping, while the real queue ARN is accepted;
    every cross-service reference is an ARN, so it must be parsed and validated rather than stored."""
    lam = ctx.client("lambda")
    sqs = ctx.client("sqs")
    bucket = _new_bucket(ctx, "esmarn")
    queue = _create_queue(ctx, "q-esmarn")
    code = """
        def handler(event, context):
            return {"count": len(event.get("Records", []))}
    """
    fn = _create_lambda(
        ctx,
        code,
        permissions=[
            {
                "Action": [
                    "sqs:ReceiveMessage",
                    "sqs:DeleteMessage",
                    "sqs:GetQueueAttributes",
                ],
                "Resource": queue["arn"],
            }
        ],
    )

    def _attempt(event_source_arn):
        return _expect_error(
            lambda: lam.create_event_source_mapping(
                EventSourceArn=event_source_arn,
                FunctionName=fn["name"],
                BatchSize=1,
                Enabled=True,
            )
        )

    # (a) Wrong resource type: a REAL ARN for a REAL resource that is not a valid event source.
    wrong_type = _attempt(f"arn:aws:s3:::{bucket}")
    expected_wrong_type = (
        "InvalidParameterValueException",
        f"Unrecognized event source. Unsupported source arn : arn:aws:s3:::{bucket}",
    )
    assert wrong_type == expected_wrong_type, (
        f"an S3 bucket ARN is not a valid EventSourceArn; expected {expected_wrong_type!r}, "
        f"got {wrong_type!r}"
    )
    # (b) Foreign account: same queue name, fabricated account id.
    foreign = _attempt(f"arn:aws:sqs:{ctx.region}:111122223333:{queue['name']}")
    prefix = (
        "Error occurred while ReceiveMessage. SQS Error Code: InvalidAddress. SQS Error Message: "
        "The address "
    )
    suffix = " is not valid for this endpoint."
    assert (
        foreign[0] == "InvalidParameterValueException"
        and foreign[1].startswith(prefix)
        and foreign[1].endswith(suffix)
    ), (
        f"a queue ARN in another account must be refused with InvalidParameterValueException "
        f"{prefix}<queue URL>{suffix!r}, got {foreign!r} -- accepting it means the account field "
        "of the ARN was never resolved"
    )
    # The queue URL the refusal names is an address: its host is environment, so the claim is an
    # http(s) URL whose path carries the foreign account and the queue name.
    address = urlsplit(foreign[1][len(prefix):-len(suffix)])
    assert (
        address.scheme in ("http", "https")
        and address.hostname
        and address.path == f"/111122223333/{queue['name']}"
    ), (
        f"the refusal must name an http(s) queue URL with path /111122223333/{queue['name']}, "
        f"got {foreign[1]!r}"
    )
    # (c) Malformed ARN.
    malformed = _attempt("not-an-arn")
    expected_malformed = (
        "ValidationException",
        "1 validation error detected: Value 'not-an-arn' at 'eventSourceArn' failed to satisfy "
        "constraint: Member must satisfy regular expression pattern: "
        r"arn:(aws[a-zA-Z0-9-]*):([a-zA-Z0-9\-])+:((eusc-)?[a-z]{2}((-gov)|(-iso([a-z]?)))?-[a-z]+-\d{1})?:(\d{12})?:(.*)",
    )
    assert malformed == expected_malformed, (
        f"a malformed EventSourceArn must be refused with {expected_malformed!r}, got {malformed!r}"
    )

    # Effect absent: not one of the three rejections created a mapping.
    mappings = lam.list_event_source_mappings(FunctionName=fn["name"])["EventSourceMappings"]
    assert mappings == [], (
        f"no event source mapping may exist after three rejected creates: {mappings!r}"
    )

    # Control: the real, same-account queue ARN is accepted and the ESM really polls the queue.
    esm = _retry_client_error(
        lambda: lam.create_event_source_mapping(
            EventSourceArn=queue["arn"], FunctionName=fn["name"], BatchSize=1, Enabled=True
        ),
        codes=("InvalidParameterValueException",),
        description="CreateEventSourceMapping with the real queue ARN (IAM propagation)",
    )
    ctx.on_cleanup(
        lambda: ctx.client("lambda").delete_event_source_mapping(UUID=esm["UUID"])
    )
    assert esm["EventSourceArn"] == queue["arn"], esm
    _poll_until(
        lambda: lam.get_event_source_mapping(UUID=esm["UUID"]),
        lambda r: r.get("State") == "Enabled",
        timeout_s=180.0,
        interval_s=5.0,
        description="the accepted event source mapping reaches Enabled",
    )
    sqs.send_message(QueueUrl=queue["url"], MessageBody="sim2real-xsvc-esm-control")
    _poll_until(
        lambda: _queue_depth(ctx, queue["url"]),
        lambda depth: depth == 0,
        timeout_s=180.0,
        interval_s=5.0,
        description="the ESM consumes the message from the accepted queue ARN",
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
