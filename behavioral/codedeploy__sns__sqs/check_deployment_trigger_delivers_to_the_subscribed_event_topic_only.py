"""deployment-trigger-delivers-to-the-subscribed-event-topic-only."""
from __future__ import annotations

import io
import json
import time

import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deployment-trigger-delivers-to-the-subscribed-event-topic-only"
GROUP = "eventing"
SERVICES = ["codedeploy", "sns", "sqs"]

TERMINAL = ("Succeeded", "Failed", "Stopped")
_INLINE_POLICY = "codedeploy-inline"
#: The notification's eventTriggerName echoes this triggerName, not the triggerEvents value.
_TRIGGER_NAME_SUCCESS = "sim2real-on-success"
_TRIGGER_NAME_FAILURE = "sim2real-on-failure"
_SRC = "def handler(event, context):\n    return {{'marker': 'v{n}'}}\n"
#: A fixed absence window, read with long polls of at most 3 s.
ABSENCE_WINDOW_S = 10.0


@tags("axis:negative-delivery", "cap:c4", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A deployment-group trigger notifies, via SNS into SQS, only the topic subscribed to the event
    that happened: success reaches the success topic only, then a failure reaches the failure topic.
    """
    cd = ctx.client("codedeploy")
    lam = ctx.client("lambda")
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")

    account = ctx.client("sts").get_caller_identity()["Account"]
    exec_role = _exec_role_arn(ctx)
    _, role_arn = _make_codedeploy_role(
        ctx,
        "sim2real-behav-role-codedeploy-",
        [
            {
                "Effect": "Allow",
                "Action": ["lambda:*", "codedeploy:*", "sns:Publish", "cloudwatch:Describe*"],
                "Resource": "*",
            }
        ],
    )

    success = _topic_with_queue(ctx, sns, sqs, account, "success")
    failure = _topic_with_queue(ctx, sns, sqs, account, "failure")
    _await_wiring(ctx, sns, sqs, success)
    _await_wiring(ctx, sns, sqs, failure)

    fn, versions, alias = _versioned_function_with_alias(ctx, lam, exec_role)
    app = _create_application(ctx, compute_platform="Lambda")
    triggers = [
        {
            "triggerName": _TRIGGER_NAME_SUCCESS,
            "triggerTargetArn": success["topic"],
            "triggerEvents": ["DeploymentSuccess"],
        },
        {
            "triggerName": _TRIGGER_NAME_FAILURE,
            "triggerTargetArn": failure["topic"],
            "triggerEvents": ["DeploymentFailure"],
        },
    ]
    dg = _create_deployment_group(
        ctx,
        app,
        deployment_config="CodeDeployDefault.LambdaAllAtOnce",
        role_arn=role_arn,
        triggerConfigurations=triggers,
    )
    stored = {
        t["triggerName"]: sorted(t["triggerEvents"])
        for t in cd.get_deployment_group(applicationName=app, deploymentGroupName=dg)[
            "deploymentGroupInfo"
        ].get("triggerConfigurations")
        or []
    }
    assert stored == {
        _TRIGGER_NAME_SUCCESS: ["DeploymentSuccess"],
        _TRIGGER_NAME_FAILURE: ["DeploymentFailure"],
    }, (
        f"GetDeploymentGroup reports triggerConfigurations {stored!r}; the two topics must be "
        f"subscribed to disjoint single events or the delivery negative below is meaningless"
    )

    # Setting triggerConfigurations publishes a one-time, non-JSON verification notification to each
    # topic; undrained, it would trip the absence check below.
    _drain_queue(sqs, success["queue"])
    _drain_queue(sqs, failure["queue"])

    # --- leg 1: a succeeding deployment, and the latency of its notification ---
    t0 = time.monotonic()
    ok_id, ok_info = _deploy_and_wait(
        ctx, cd, app, dg, _lambda_revision(fn, alias, versions[0], versions[1])
    )
    assert ok_info.get("status") == "Succeeded", (
        f"the deployment {ok_id!r} that must fire the DeploymentSuccess trigger ended "
        f"{ok_info.get('status')!r} with errorInformation {ok_info.get('errorInformation')!r}"
    )
    body = _await_notification(
        ctx, sqs, success["queue"], ok_id, timeout_s=_budget_s(ctx, 180),
        what="the DeploymentSuccess notification"
    )
    latency = time.monotonic() - t0
    _assert_trigger_body(body, ok_id, app, dg, _TRIGGER_NAME_SUCCESS, "succeeded", ctx.region)

    # --- leg 2: the failure topic received nothing, on a fixed window ---
    _assert_queue_silent(
        sqs,
        failure["queue"],
        ABSENCE_WINDOW_S,
        (
            f"a trigger subscribed ONLY to DeploymentFailure must publish nothing for the "
            f"SUCCEEDING deployment {ok_id!r}, whose success notification has already arrived"
        ),
    )

    # --- leg 3: positive control -- a failing deployment, so the failure topic must deliver ---
    bad_id, bad_info = _deploy_and_wait(
        ctx, cd, app, dg, _lambda_revision(fn, _absent_alias(ctx), versions[1], versions[2])
    )
    assert bad_info.get("status") == "Failed", (
        f"the deployment naming an alias that does not exist ended {bad_info.get('status')!r} "
        f"on {bad_id!r} (errorInformation={bad_info.get('errorInformation')!r}), expected "
        f"'Failed'. The DeploymentFailure trigger cannot be shown to work without a deployment "
        f"that genuinely fails"
    )
    bad_body = _await_notification(
        ctx,
        sqs,
        failure["queue"],
        bad_id,
        timeout_s=_budget_s(ctx, max(180.0, 6 * latency)),
        what=(
            f"the DeploymentFailure notification for {bad_id!r}. The success topic delivered in "
            f"{latency:.1f}s on the same wiring, so a failure topic that never delivers is a "
            f"missing publish and not a slow one -- and it would mean the empty-queue assertion "
            f"above proved only that nothing is wired"
        ),
    )
    _assert_trigger_body(bad_body, bad_id, app, dg, _TRIGGER_NAME_FAILURE, "failed", ctx.region)

    # --- leg 4: and the filter held in the other direction too ---
    _assert_queue_silent(
        sqs,
        success["queue"],
        ABSENCE_WINDOW_S,
        (
            f"a trigger subscribed ONLY to DeploymentSuccess must publish nothing for the "
            f"FAILING deployment {bad_id!r}; the success queue was drained after its own "
            f"notification, so anything here is a second, wrong delivery"
        ),
    )


def _topic_with_queue(ctx, sns, sqs, account, label):
    """An SNS topic and a dedicated SQS queue subscribed to it.

    One queue per topic, so "the failure topic delivered nothing" is attributable to one topic.
    """
    topic_name = ctx.unique_name(f"sim2real-behav-cd-{label}-")
    topic = sns.create_topic(
        Name=topic_name,
        Tags=[
            {"Key": "sim2real:managed", "Value": "true"},
            {"Key": "sim2real", "Value": CHECK},
        ],
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic))

    queue_name = ctx.unique_name(f"sim2real-behav-cd-{label}-q-")
    queue = sqs.create_queue(
        QueueName=queue_name,
        tags={"sim2real:managed": "true", "sim2real": CHECK},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue))
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]
    sqs.set_queue_attributes(
        QueueUrl=queue,
        Attributes={
            "Policy": json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"Service": "sns.amazonaws.com"},
                            "Action": "sqs:SendMessage",
                            "Resource": queue_arn,
                            "Condition": {"ArnEquals": {"aws:SourceArn": topic}},
                        }
                    ],
                }
            )
        },
    )
    sub = sns.subscribe(TopicArn=topic, Protocol="sqs", Endpoint=queue_arn)[
        "SubscriptionArn"
    ]
    ctx.on_cleanup(lambda: sns.unsubscribe(SubscriptionArn=sub))
    assert account in queue_arn, (
        f"the queue ARN {queue_arn!r} is not in the caller's account ({account!r}); the queue "
        f"policy's SourceArn condition would not match and delivery would be silently denied"
    )
    return {"topic": topic, "queue": queue, "arn": queue_arn, "sub": sub}


def _drain_queue(sqs, queue_url, *, quiet_polls=2):
    """Discard every message on `queue_url`, stopping once `quiet_polls` consecutive long-polls
    come back empty."""
    empty_run = 0
    while empty_run < quiet_polls:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=3)
        msgs = resp.get("Messages") or []
        if not msgs:
            empty_run += 1
            continue
        empty_run = 0
        for msg in msgs:
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])


def _await_notification(ctx, sqs, queue_url, deployment_id, *, timeout_s, what):
    """Receive until a notification NAMING `deployment_id` arrives; return its decoded body.

    Other messages are deleted as drained, so later silence assertions start from an empty queue.
    """
    deadline = time.monotonic() + timeout_s
    seen = []
    while time.monotonic() < deadline:
        resp = sqs.receive_message(
            QueueUrl=queue_url,
            MaxNumberOfMessages=10,
            WaitTimeSeconds=2,
            MessageAttributeNames=["All"],
        )
        for msg in resp.get("Messages") or []:
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            body = _decode(msg["Body"])
            seen.append(body)
            if body.get("deploymentId") == deployment_id:
                return body
    if _budget_spent(ctx):
        raise TimeoutError(f"{what} on {queue_url!r}: the run budget ended first; not graded")
    raise AssertionError(
        f"timed out after {timeout_s}s waiting for {what} on {queue_url!r}. The notifications "
        f"that DID arrive were {seen!r}; none carried deploymentId {deployment_id!r}, which was "
        f"minted by this run and so cannot come from a recording"
    )


def _decode(raw):
    """The trigger payload out of the SNS envelope.

    The subscription is not raw-delivery, so `Message` holds the trigger body as a JSON string;
    anything else comes back as a diagnostic dict so the caller reports what arrived.
    """
    try:
        envelope = json.loads(raw)
    except json.JSONDecodeError:
        return {"_unparsed_envelope": raw[:400]}
    inner = envelope.get("Message")
    if isinstance(inner, str):
        try:
            return json.loads(inner)
        except json.JSONDecodeError:
            return {"_unparsed_message": inner[:400], "_envelope_keys": sorted(envelope)}
    return {"_no_message_field": sorted(envelope)}


def _assert_trigger_body(body, dep_id, app, dg, trigger_name, want_status, region):
    """Every field the notification must carry, each asserted separately so they fail apart."""
    assert body.get("deploymentId") == dep_id, (
        f"the notification's deploymentId reads {body.get('deploymentId')!r}, expected "
        f"{dep_id!r}. Full body: {body!r}"
    )
    assert body.get("applicationName") == app, (
        f"the notification's applicationName reads {body.get('applicationName')!r}, expected "
        f"{app!r}; a notification that does not identify its application is unusable for "
        f"routing. Full body: {body!r}"
    )
    assert body.get("deploymentGroupName") == dg, (
        f"the notification's deploymentGroupName reads {body.get('deploymentGroupName')!r}, "
        f"expected {dg!r}. Full body: {body!r}"
    )
    # eventTriggerName echoes the configured triggerName, never the triggerEvents value.
    assert body.get("eventTriggerName") == trigger_name, (
        f"the notification's eventTriggerName reads {body.get('eventTriggerName')!r}, expected "
        f"{trigger_name!r} -- the configured triggerName, not the triggerEvents value -- so a "
        f"consumer subscribed to several triggers can tell them apart. Full body: {body!r}"
    )
    got_status = str(body.get("status") or "")
    assert got_status.lower() == want_status, (
        f"the notification's status reads {got_status!r}, expected {want_status!r} "
        f"(case-insensitively -- the casing of this field is not in the Smithy model and is one "
        f"of this draft's hypotheses). Full body: {body!r}"
    )
    assert body.get("region") == region, (
        f"the notification's region reads {body.get('region')!r}, expected {region!r}. Full "
        f"body: {body!r}"
    )


def _assert_queue_silent(sqs, queue_url, window_s, reason):
    """Nothing arrives for `window_s`, on TWO independent observables.

    A receive alone can miss an in-flight message and the queue attribute alone lags.
    """
    deadline = time.monotonic() + window_s
    while time.monotonic() < deadline:
        wait_s = max(1, min(3, int(deadline - time.monotonic())))
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=wait_s
        )
        arrived = resp.get("Messages") or []
        assert not arrived, (
            f"{len(arrived)} message(s) arrived on {queue_url!r} when none should have. "
            f"{reason}. Bodies: {[_decode(m['Body']) for m in arrived]!r}"
        )
    attrs = sqs.get_queue_attributes(
        QueueUrl=queue_url,
        AttributeNames=["ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible"],
    )["Attributes"]
    assert attrs["ApproximateNumberOfMessages"] == "0", (
        f"{queue_url!r} reports ApproximateNumberOfMessages "
        f"{attrs['ApproximateNumberOfMessages']!r} after {window_s:.1f}s of empty receives. "
        f"{reason}. A receive can miss an in-flight message that this attribute counts, which "
        f"is why both are asserted"
    )
    assert attrs["ApproximateNumberOfMessagesNotVisible"] == "0", (
        f"{queue_url!r} reports ApproximateNumberOfMessagesNotVisible "
        f"{attrs['ApproximateNumberOfMessagesNotVisible']!r}; a message in flight is a delivery "
        f"that happened. {reason}"
    )


def _absent_alias(ctx):
    """A unique alias name this check never creates, used to drive a deployment to Failed."""
    return ctx.unique_name("sim2real-absent-alias-")


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _await_wiring(ctx, sns, sqs, wiring):
    """Poll until the SQS subscription is confirmed and the queue policy names the topic."""
    sub_arn = wiring["sub"]
    _poll(
        lambda: sns.get_subscription_attributes(SubscriptionArn=sub_arn)["Attributes"].get(
            "PendingConfirmation"
        ),
        lambda v: v != "true",
        timeout_s=_budget_s(ctx, 60),
        interval_s=1,
        ctx=ctx,
        what=f"the SQS subscription {sub_arn!r} to be confirmed",
    )
    _poll(
        lambda: sqs.get_queue_attributes(QueueUrl=wiring["queue"], AttributeNames=["Policy"])[
            "Attributes"
        ].get("Policy", ""),
        lambda pol: wiring["topic"] in pol,
        timeout_s=_budget_s(ctx, 60),
        interval_s=1,
        ctx=ctx,
        what=f"the queue policy on {wiring['queue']!r} to admit {wiring['topic']!r}",
    )


def _poll(fn, pred, *, timeout_s, interval_s, what, ctx=None):
    """Bounded retry with a deadline; raises on timeout."""
    deadline = time.monotonic() + timeout_s
    val = fn()
    while not pred(val):
        if time.monotonic() >= deadline:
            if ctx is not None and _budget_spent(ctx):
                raise TimeoutError(f"{what}: the run budget ended first; not graded")
            raise AssertionError(
                f"timed out after {timeout_s}s waiting for {what}; the last value observed was "
                f"{val!r}"
            )
        time.sleep(interval_s)
        val = fn()
    return val


def _deploy_and_wait(ctx, cd, app, dg, revision, *, timeout_s=600, **extra):
    dep_id = cd.create_deployment(
        applicationName=app, deploymentGroupName=dg, revision=revision, **extra
    )["deploymentId"]
    _register_deployment_teardown(ctx, cd, dep_id)
    info = _poll(
        lambda: cd.get_deployment(deploymentId=dep_id)["deploymentInfo"],
        lambda i: i.get("status") in TERMINAL,
        timeout_s=_budget_s(ctx, timeout_s),
        interval_s=1,
        ctx=ctx,
        what=f"deployment {dep_id!r} to reach one of {TERMINAL!r}",
    )
    return dep_id, info


def _register_deployment_teardown(ctx, cd, dep_id):
    def _teardown():
        try:
            cd.stop_deployment(deploymentId=dep_id, autoRollbackEnabled=False)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in (
                "DeploymentAlreadyCompletedException",
                "InvalidDeploymentStatusException",
            ):
                raise
        deadline = time.monotonic() + 300
        while time.monotonic() < deadline:
            status = cd.get_deployment(deploymentId=dep_id)["deploymentInfo"].get("status")
            if status in TERMINAL:
                return
            time.sleep(2)
        raise AssertionError(
            f"deployment {dep_id} did not reach a terminal state within the teardown deadline"
        )

    ctx.on_cleanup(_teardown)


def _create_application(ctx, compute_platform="Lambda"):
    cd = ctx.client("codedeploy")
    name = ctx.unique_name("sim2real-behav-cd-app-")
    cd.create_application(
        applicationName=name,
        computePlatform=compute_platform,
        tags=[
            {"Key": "sim2real:managed", "Value": "true"},
            {"Key": "sim2real", "Value": CHECK},
        ],
    )
    ctx.on_cleanup(lambda: cd.delete_application(applicationName=name))
    return name


def _make_codedeploy_role(ctx, prefix, statements):
    iam = ctx.client("iam")
    role_name = ctx.unique_name(prefix)
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "codedeploy.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Path="/sim2real/",
        Tags=[
            {"Key": "sim2real:managed", "Value": "true"},
            {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
        ],
    )

    def _del_role():
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_del_role)
    _put_service_role_policy(ctx, role_name, statements)
    return role_name, resp["Role"]["Arn"]


def _put_service_role_policy(ctx, role_name, statements):
    ctx.client("iam").put_role_policy(
        RoleName=role_name,
        PolicyName=_INLINE_POLICY,
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )


def _create_deployment_group(ctx, app, *, deployment_config, role_arn, name=None, **extra):
    cd = ctx.client("codedeploy")
    name = name or ctx.unique_name("sim2real-behav-cd-dg-")
    kwargs = {
        "applicationName": app,
        "deploymentGroupName": name,
        "deploymentConfigName": deployment_config,
        "serviceRoleArn": role_arn,
        "deploymentStyle": {
            "deploymentType": "BLUE_GREEN",
            "deploymentOption": "WITH_TRAFFIC_CONTROL",
        },
    }
    kwargs.update(extra)
    deadline = time.monotonic() + _budget_s(ctx, 90)
    while True:
        try:
            cd.create_deployment_group(**kwargs)
            break
        except ClientError as exc:
            err = exc.response.get("Error", {})
            msg = (err.get("Message") or "").lower()
            transient = err.get("Code") == "InvalidRoleException" and (
                "assume" in msg or "not authorized" in msg or "permissions required" in msg
            )
            if transient and time.monotonic() < deadline:
                time.sleep(3)
                continue
            if transient and _budget_spent(ctx):
                raise TimeoutError("CreateDeploymentGroup past the service role's propagation: the run budget ended first; not graded") from exc
            raise
    ctx.on_cleanup(
        lambda: cd.delete_deployment_group(applicationName=app, deploymentGroupName=name)
    )
    return name


def _lambda_zip(src):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        info = zipfile.ZipInfo("lambda_function.py")
        info.external_attr = 0o644 << 16
        zf.writestr(info, src)
    return buf.getvalue()


def _exec_role_arn(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-cd-exec-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Path="/sim2real/",
        Tags=[
            {"Key": "sim2real:managed", "Value": "true"},
            {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
        ],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return arn


def _versioned_function_with_alias(ctx, lam, exec_role, n_versions=3, alias="live"):
    """A function with `n_versions` distinct published versions and an alias on the first.

    Each version's body returns a marker naming its own version, so a later invoke can tell
    which code actually ran rather than trusting a label.
    """
    fn = ctx.unique_name("sim2real-behav-cd-fn-")
    deadline = time.monotonic() + _budget_s(ctx, 180)
    while True:
        try:
            lam.create_function(
                FunctionName=fn,
                Runtime="python3.12",
                Role=exec_role,
                Handler="lambda_function.handler",
                Code={"ZipFile": _lambda_zip(_SRC.format(n=1))},
                Timeout=15,
                Publish=False,
                Tags={"sim2real:managed": "true", "sim2real": CHECK},
            )
            break
        except ClientError as exc:
            err = exc.response["Error"]
            retryable = err["Code"] == "InvalidParameterValueException" and (
                "role" in (err.get("Message") or "").lower()
            )
            if retryable and time.monotonic() < deadline:
                time.sleep(3)
                continue
            if retryable and _budget_spent(ctx):
                raise TimeoutError("CreateFunction past the execution role's propagation: the run budget ended first; not graded") from exc
            raise
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn))
    _wait_active(lam, fn)
    versions = [lam.publish_version(FunctionName=fn)["Version"]]
    for n in range(2, n_versions + 1):
        lam.update_function_code(FunctionName=fn, ZipFile=_lambda_zip(_SRC.format(n=n)))
        _wait_updated(lam, fn)
        versions.append(lam.publish_version(FunctionName=fn)["Version"])
    assert len(set(versions)) == n_versions, (
        f"setup: publishing {n_versions} versions produced {versions!r}, which are not all "
        f"distinct; every assertion below distinguishes versions by identity"
    )
    lam.create_alias(FunctionName=fn, Name=alias, FunctionVersion=versions[0])
    return fn, versions, alias


def _wait_active(lam, fn, timeout_s=180):
    _poll(
        lambda: lam.get_function(FunctionName=fn)["Configuration"]["State"],
        lambda s: s == "Active",
        timeout_s=timeout_s,
        interval_s=2,
        what=f"function {fn!r} to become Active",
    )


def _wait_updated(lam, fn, timeout_s=180):
    _poll(
        lambda: lam.get_function(FunctionName=fn)["Configuration"]["LastUpdateStatus"],
        lambda s: s == "Successful",
        timeout_s=timeout_s,
        interval_s=2,
        what=f"the code update on {fn!r} to finish",
    )


def _lambda_revision(fn, alias, current, target):
    return {
        "revisionType": "AppSpecContent",
        "appSpecContent": {
            "content": json.dumps(
                {
                    "version": "0.0",
                    "Resources": [
                        {
                            "sim2realFunction": {
                                "Type": "AWS::Lambda::Function",
                                "Properties": {
                                    "Name": fn,
                                    "Alias": alias,
                                    "CurrentVersion": current,
                                    "TargetVersion": target,
                                },
                            }
                        }
                    ],
                }
            )
        },
    }


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
