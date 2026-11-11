"""webhook-url-rejects-a-wrong-hmac-signature-and-starts-no-execution."""
from __future__ import annotations

import hashlib
import hmac
import json
import time
import urllib.error
import urllib.request

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "webhook-url-rejects-a-wrong-hmac-signature-and-starts-no-execution"
GROUP = "overly-permissive"
SERVICES = ["codepipeline"]

_SCENARIO = "codepipeline-webhook-hmac"
_BODY = {"ref": "refs/heads/main", "repository": {"name": "sim2real-probe"}}


@tags("axis:negative-delivery", "cap:c1", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A correctly signed GITHUB_HMAC POST to the webhook URL starts an execution, a wrong-secret
    POST is acked with 2xx but starts none, and the correctly signed POST starts one again.

    Reference: https://docs.aws.amazon.com/codepipeline/latest/APIReference/API_PutWebhook.html
    """
    cp = ctx.client("codepipeline")
    s3 = ctx.client("s3")
    create_timeout_s = 240
    settle_timeout_s = 120

    secret = f"sim2real-{ctx.unique_name('s-')}"
    wrong_secret = f"{secret}-not-the-secret"

    bucket = _artifact_bucket(ctx, s3)
    role_arn = _pipeline_role(ctx, bucket)
    action_type_id = _custom_source_action_type(ctx, cp)

    name = ctx.unique_name("sim2real-behav-cpwh-")
    _create_with_role_propagation(
        cp, _pipeline(name, role_arn, bucket, action_type_id), timeout_s=create_timeout_s)
    ctx.on_cleanup(lambda: cp.delete_pipeline(name=name))

    # CreatePipeline starts an execution of its own; it must land in the baseline before the
    # webhook POST, or its late arrival looks like a second webhook-triggered execution.
    initial_execution_id = _poll(
        lambda: _execution_ids(cp, name), lambda ids: len(ids) >= 1,
        timeout_s=settle_timeout_s, interval_s=3,
        what=f"CreatePipeline's own automatic execution of {name!r} to appear")[0]
    ctx.on_cleanup(lambda: _abandon(cp, name, initial_execution_id))

    webhook_name = ctx.unique_name("sim2real-behav-cpwh-")
    put = cp.put_webhook(
        webhook={
            "name": webhook_name,
            "targetPipeline": name,
            "targetAction": "Source",
            "filters": [{"jsonPath": "$.ref", "matchEquals": _BODY["ref"]}],
            "authentication": "GITHUB_HMAC",
            "authenticationConfiguration": {"SecretToken": secret},
        },
        tags=[{"key": "sim2real", "value": _SCENARIO}],
    )
    ctx.on_cleanup(lambda: cp.delete_webhook(name=webhook_name))
    url = put["webhook"]["url"]
    assert not (p := ctx.published_url_mismatch(url, labels=(ctx.region, "webhooks"), path="/trigger")), p
    # The secret is documented as redacted in the PutWebhook response.
    echoed = put["webhook"]["definition"]["authenticationConfiguration"].get("SecretToken")
    assert echoed != secret, (
        f"the webhook secret must be redacted in the PutWebhook response, not echoed verbatim; "
        f"got {echoed!r} which equals the secret that was supplied"
    )

    baseline = _execution_ids(cp, name)
    baseline_trigger = _trigger_type(cp, name, baseline[0]) if baseline else None

    # Positive control: correctly signed.
    started = time.monotonic()
    status, body = _post(ctx, url, _BODY, secret)
    assert 200 <= status < 300, (
        f"a correctly signed webhook payload must be accepted by {url!r}; expected a 2xx, got "
        f"HTTP {status} with body {body[:200]!r}. If this fails, every absence assertion below "
        f"would pass against an endpoint that refuses everything."
    )
    first = _await_new_execution(cp, name, baseline, timeout_s=settle_timeout_s,
                                 why="the correctly signed webhook POST")
    control_latency_s = time.monotonic() - started
    ctx.on_cleanup(lambda: _abandon(cp, name, first))
    trigger = _trigger_type(cp, name, first)
    assert trigger and trigger != baseline_trigger, (
        f"the execution started by the webhook must be attributed to the webhook trigger, not to "
        f"the same trigger type as the CreatePipeline execution: got triggerType {trigger!r}, "
        f"baseline was {baseline_trigger!r} (H4)"
    )

    after_first = _execution_ids(cp, name)

    # Wrong secret. AWS acks any well-formed POST with 2xx and validates GITHUB_HMAC asynchronously,
    # so only the absence of a new execution shows the refusal.
    bad_status, bad_body = _post(ctx, url, _BODY, wrong_secret)
    assert 200 <= bad_status < 300, (
        f"the webhook trigger endpoint must ack a well-formed POST with 2xx regardless of "
        f"whether its HMAC signature later validates -- CodePipeline enforces GITHUB_HMAC "
        f"asynchronously, not in the HTTP response (H3): expected a 2xx from {url!r} for the "
        f"wrong-secret POST too, got HTTP {bad_status} with body {bad_body[:200]!r}"
    )

    # No execution may start, held for 3x the control's measured latency.
    window_s = max(3.0 * control_latency_s, 15.0)
    deadline = time.monotonic() + window_s
    while True:
        now_ids = _execution_ids(cp, name)
        new = [i for i in now_ids if i not in after_first]
        assert new == [], (
            f"the wrong-signature POST was refused, so it must not have started an execution of "
            f"{name!r}: new execution ids {new!r} appeared within a {window_s:.0f}s window "
            f"(3x the correctly signed POST's measured {control_latency_s:.1f}s)"
        )
        assert len(now_ids) == len(after_first), (
            f"the execution count for {name!r} must be unchanged by a refused POST: expected "
            f"{len(after_first)}, got {len(now_ids)} ({now_ids!r})"
        )
        if time.monotonic() >= deadline:
            break
        time.sleep(5)

    # Restore the correct signature; the identical POST works again.
    ok_status, ok_body = _post(ctx, url, _BODY, secret)
    assert 200 <= ok_status < 300, (
        f"signing with the correct secret again must be accepted: expected a 2xx from {url!r}, "
        f"got HTTP {ok_status} with body {ok_body[:200]!r}"
    )
    second = _await_new_execution(cp, name, after_first, timeout_s=settle_timeout_s,
                                  why="the restored correctly signed webhook POST")
    ctx.on_cleanup(lambda: _abandon(cp, name, second))
    assert second != first, (
        f"the restored POST must start a NEW execution, not resurface the first: got {second!r}, "
        f"first was {first!r}"
    )
    assert _trigger_type(cp, name, second) == trigger, (
        f"the second webhook-started execution must carry the same triggerType as the first: "
        f"expected {trigger!r}, got {_trigger_type(cp, name, second)!r}"
    )

    # The webhook must still be listed and still report the same URL, so the refusal above was
    # authentication doing its job rather than the webhook having been torn down mid-check.
    listed = [w for w in _webhooks(cp) if w["definition"]["name"] == webhook_name]
    assert len(listed) == 1 and listed[0]["url"] == url, (
        f"exactly one webhook named {webhook_name!r} must still be listed with url {url!r}; got "
        f"{listed!r}"
    )


def _poll(fn, pred, *, timeout_s, interval_s, what):
    """A bounded retry that raises on timeout, so a truncated wait never passes as satisfied."""
    deadline = time.monotonic() + timeout_s
    val = fn()
    while not pred(val):
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"timed out after {timeout_s}s waiting for {what}; last observed value {val!r}"
            )
        time.sleep(interval_s)
        val = fn()
    return val


def _post(ctx, url, payload, signing_secret):
    """POST the payload signed with signing_secret under both GitHub signature headers.

    Returns (http_status, body_text); an HTTPError becomes a value, a URLError propagates.
    """
    body = json.dumps(payload).encode()
    sha1 = hmac.new(signing_secret.encode(), body, hashlib.sha1).hexdigest()
    sha256 = hmac.new(signing_secret.encode(), body, hashlib.sha256).hexdigest()
    target_url, route_headers = ctx.endpoint_route(url)
    req = urllib.request.Request(
        target_url, data=body, method="POST",
        headers={
            "Content-Type": "application/json",
            "X-GitHub-Event": "push",
            "X-Hub-Signature": f"sha1={sha1}",
            "X-Hub-Signature-256": f"sha256={sha256}",
            **route_headers,
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")


def _account_id(ctx) -> str:
    return ctx.client("sts").get_caller_identity()["Account"]


def _purge_bucket(s3, bucket) -> None:
    for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
        objs = [
            {"Key": v["Key"], "VersionId": v["VersionId"]}
            for v in list(page.get("Versions", [])) + list(page.get("DeleteMarkers", []))
        ]
        if objs:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objs}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=bucket)


def _artifact_bucket(ctx, s3) -> str:
    bucket = ctx.unique_name("sim2real-behav-cpwh-").lower()
    kw = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        kw["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kw)
    ctx.on_cleanup(lambda: _purge_bucket(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket,
                          Tagging={"TagSet": [{"Key": "sim2real", "Value": _SCENARIO}]})
    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
    return bucket


def _pipeline_role(ctx, bucket) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-cpwh-")
    iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Service": "codepipeline.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }],
        }),
        Tags=[{"Key": "sim2real", "Value": _SCENARIO}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.put_role_policy(
        RoleName=name, PolicyName="artifacts",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:GetObjectVersion", "s3:PutObject",
                           "s3:GetBucketVersioning", "s3:ListBucket"],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            }],
        }),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="artifacts"))
    return f"arn:aws:iam::{_account_id(ctx)}:role/{name}"


def _custom_source_action_type(ctx, cp):
    """A custom SOURCE action type, created or adopted; no job worker runs, so executions park."""
    provider = ctx.unique_name("SimWhSrc")[:25]
    action_type_id = {"category": "Source", "owner": "Custom",
                      "provider": provider, "version": "1"}
    try:
        cp.create_custom_action_type(
            category="Source", provider=provider, version="1",
            inputArtifactDetails={"minimumCount": 0, "maximumCount": 0},
            outputArtifactDetails={"minimumCount": 1, "maximumCount": 1},
            tags=[{"key": "sim2real", "value": _SCENARIO}],
        )
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "InvalidStructureException":
            raise
    ctx.on_cleanup(lambda: cp.delete_custom_action_type(
        category="Source", provider=provider, version="1"))
    return action_type_id


def _create_with_role_propagation(cp, declaration, *, timeout_s):
    """CreatePipeline answers InvalidStructureException while a fresh role is still propagating, so
    retry it within a bound."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return cp.create_pipeline(pipeline=declaration)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            transient = (err.get("Code") == "InvalidStructureException"
                         and "AssumeRole" in err.get("Message", ""))
            if not transient or time.monotonic() >= deadline:
                raise
            time.sleep(5)


def _pipeline(name, role_arn, bucket, action_type_id):
    """A custom source action feeding an S3 Deploy; the execution parks at the source action."""
    return {
        "name": name,
        "roleArn": role_arn,
        "artifactStore": {"type": "S3", "location": bucket},
        "pipelineType": "V2",
        "executionMode": "QUEUED",
        "stages": [
            {"name": "Source", "actions": [{
                "name": "Source",
                "actionTypeId": action_type_id,
                "runOrder": 1,
                "outputArtifacts": [{"name": "SourceOutput"}],
            }]},
            {"name": "Deploy", "actions": [{
                "name": "Deploy",
                "actionTypeId": {"category": "Deploy", "owner": "AWS", "provider": "S3",
                                 "version": "1"},
                "runOrder": 1,
                "configuration": {"BucketName": bucket, "Extract": "false",
                                  "ObjectKey": f"{name}/out.zip"},
                "inputArtifacts": [{"name": "SourceOutput"}],
            }]},
        ],
    }


def _execution_ids(cp, name):
    ids = []
    for page in cp.get_paginator("list_pipeline_executions").paginate(pipelineName=name):
        ids.extend(s["pipelineExecutionId"] for s in page.get("pipelineExecutionSummaries", []))
    return ids


def _await_new_execution(cp, name, known, *, timeout_s, why):
    ids = _poll(lambda: [i for i in _execution_ids(cp, name) if i not in known],
                lambda new: len(new) >= 1, timeout_s=timeout_s, interval_s=3,
                what=f"{why} to start a new execution of {name!r} (known ids {known!r})")
    assert len(ids) == 1, (
        f"{why} must start exactly one execution of {name!r}; got {len(ids)}: {ids!r}"
    )
    return ids[0]


def _trigger_type(cp, name, execution_id):
    """The execution's triggerType, or None when the service omits `trigger`."""
    execution = cp.get_pipeline_execution(
        pipelineName=name, pipelineExecutionId=execution_id)["pipelineExecution"]
    return (execution.get("trigger") or {}).get("triggerType")


def _webhooks(cp):
    out, token = [], None
    while True:
        kw = {"NextToken": token} if token else {}
        page = cp.list_webhooks(**kw)
        out.extend(page.get("webhooks", []))
        token = page.get("NextToken")
        if not token:
            return out


def _abandon(cp, name, execution_id):
    try:
        cp.stop_pipeline_execution(
            pipelineName=name, pipelineExecutionId=execution_id, abandon=True,
            reason="sim2real behavioral check teardown")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "PipelineNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
