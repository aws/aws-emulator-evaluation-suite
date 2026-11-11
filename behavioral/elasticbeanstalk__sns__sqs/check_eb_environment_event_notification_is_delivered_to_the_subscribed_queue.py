"""eb-environment-event-notification-is-delivered-to-the-subscribed-queue."""
from __future__ import annotations

import http.client
import io
import json
import math
import time
import urllib.error
import urllib.request
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "eb-environment-event-notification-is-delivered-to-the-subscribed-queue"
GROUP = "events"
SERVICES = ["elasticbeanstalk", "sns", "sqs"]

#: Lets a Ready environment with nothing listening on the CNAME fail as a missing data plane.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

#: CreateEnvironment refusals that mean "the IAM principal this check just created is not visible
#: to Elastic Beanstalk yet". Retried, bounded, in `_create_env`; anything else re-raises.
_IAM_PROPAGATION_CODES = frozenset({"InvalidParameterValue", "InsufficientPrivilegesException"})

#: The deployed application: stdlib only, so every HTTP assertion is over a nonce the check minted.
#:
#: Routes:
#:   /                  -> "sim2real-nonce=<NONCE>" (200), or "degraded <NONCE>" (500) once
#:                         /sim2real/fail-on has been called
#:   /sim2real/env      -> JSON of every SIM2REAL_* variable in the process environment
#:   /sim2real/boot     -> JSON {boot, nonce, uptime_s, hits}; `boot` is minted once per PROCESS
#:                         start, so it changes on any app-server restart and `hits` resets with it
#:   /sim2real/file?<p> -> the contents of the on-instance path <p>, or 404
#:   /sim2real/log      -> writes "SIM2REAL-LOG-LINE <NONCE>" to the process stdout and echoes it
#:   /sim2real/fail-on  -> subsequent "/" requests answer 500
#:   /sim2real/fail-off -> subsequent "/" requests answer 200 again
_SERVER_PY = '''
import json
import os
import sys
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BOOT = uuid.uuid4().hex
START = time.time()
STATE = {"fail": False, "hits": 0}


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _send(self, code, body):
        b = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        p = self.path.split("?")[0]
        q = self.path.split("?", 1)[1] if "?" in self.path else ""
        if p == "/sim2real/env":
            self._send(200, json.dumps(
                {k: v for k, v in os.environ.items() if k.startswith("SIM2REAL_")},
                sort_keys=True))
        elif p == "/sim2real/boot":
            STATE["hits"] += 1
            self._send(200, json.dumps(
                {"boot": BOOT, "nonce": NONCE, "hits": STATE["hits"],
                 "uptime_s": round(time.time() - START, 3)}, sort_keys=True))
        elif p == "/sim2real/file":
            try:
                with open(q) as f:
                    self._send(200, f.read())
            except OSError as exc:
                self._send(404, "no-such-file " + q + ": " + str(exc))
        elif p == "/sim2real/log":
            line = "SIM2REAL-LOG-LINE " + NONCE
            sys.stdout.write(line + chr(10))
            sys.stdout.flush()
            self._send(200, line)
        elif p == "/sim2real/fail-on":
            STATE["fail"] = True
            self._send(200, "fail-on " + NONCE)
        elif p == "/sim2real/fail-off":
            STATE["fail"] = False
            self._send(200, "fail-off " + NONCE)
        elif STATE["fail"]:
            self._send(500, "degraded " + NONCE)
        else:
            self._send(200, "sim2real-nonce=" + NONCE)


ThreadingHTTPServer(("0.0.0.0", int(os.environ.get("PORT", "8000"))), H).serve_forever()
'''


def _app_zip(nonce: str, extra: dict[str, str] | None = None) -> bytes:
    """A source bundle serving ``nonce``: a Procfile web command plus the stdlib server above.

    ``extra`` adds arbitrary members (a `.ebextensions/*.config`, a static asset).
    """
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("Procfile", "web: python3 -u server.py\n")
        z.writestr("server.py", "NONCE = " + repr(nonce) + "\n" + _SERVER_PY)
        for name, body in (extra or {}).items():
            z.writestr(name, body)
    return buf.getvalue()


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll(probe, pred, *, timeout_s: float, interval_s: float, what: str, ctx=None):
    """Poll ``probe()`` until ``pred`` holds; raise AssertionError quoting the last value."""
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if pred(last):
            return last
        if time.monotonic() >= deadline:
            if ctx is not None and _budget_spent(ctx):
                raise TimeoutError(f"{what}: the run budget ended first; not graded")
            raise AssertionError(f"{what} not reached within {timeout_s:.0f}s; last was {last!r}")
        time.sleep(interval_s)


def _describe_env(eb, env_name):
    envs = eb.describe_environments(
        EnvironmentNames=[env_name], IncludeDeleted=True).get("Environments") or []
    return envs[0] if envs else None


def _http_get(url: str, timeout: float = 20.0):
    """(status, body) for a plain HTTP GET; an HTTP error status is a result, not an exception."""
    req = urllib.request.Request(url, headers={"User-Agent": "sim2real-eb-behavioral"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")


def _http_probe(url: str, timeout: float = 8.0):
    """(status, body) where a transport failure becomes the status ``"<no-response>"``.

    Used where unreachability is the measurement rather than an error.
    """
    try:
        return _http_get(url, timeout=timeout)
    except (OSError, http.client.HTTPException) as exc:
        # Narrow on purpose: a refused connection, a reset and a truncated status line are the
        # measurement; anything else propagates.
        return "<no-response>", f"{type(exc).__name__}: {exc}"


def _http_until(url: str, pred, *, timeout_s: float, interval_s: float = 10.0, what: str):
    """Poll a real HTTP GET until ``pred((status, body))`` holds.

    A connection failure after the budget fails: a Ready environment nobody can reach is a defect.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        last = _http_probe(url, timeout=20.0)
        if pred(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{DATAPLANE_MARKER}: {what} — nothing satisfying the condition came back from "
                f"{url!r} within {timeout_s}s; last outcome {last!r}. A provisioned-but-"
                f"unconnectable environment is a failure, not an environment limitation.")
        time.sleep(interval_s)


def _solution_stack(eb) -> str:
    """A current AL2023 Python solution stack, resolved from the service, never hardcoded.

    Python: its streamed log set is documented and the bundle is stdlib-only.
    """
    stacks = eb.list_available_solution_stacks().get("SolutionStacks") or []
    py = [s for s in stacks if "Amazon Linux 2023" in s and "running Python" in s]
    assert py, (
        f"this check needs an Amazon Linux 2023 Python solution stack; "
        f"ListAvailableSolutionStacks offered none, returning {stacks[:12]!r}")
    return py[0]


def _eb_iam(ctx, marker: str, extra_instance_policies=()):
    """The instance profile + service role an environment needs, with LIFO teardown.

    Raises if IAM is unreachable rather than launching without an instance profile.
    """
    iam = ctx.client("iam")

    def _role(name, service, policies):
        trust = {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Principal": {"Service": service}, "Action": "sts:AssumeRole"}]}
        iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
                        Tags=[{"Key": "sim2real", "Value": marker}])
        ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
        for arn in policies:
            iam.attach_role_policy(RoleName=name, PolicyArn=arn)
            ctx.on_cleanup(lambda a=arn: iam.detach_role_policy(RoleName=name, PolicyArn=a))

    ec2_role = ctx.unique_name("sim2real-eb-ec2-role-")
    svc_role = ctx.unique_name("sim2real-eb-svc-role-")
    profile = ctx.unique_name("sim2real-eb-profile-")
    _role(ec2_role, "ec2.amazonaws.com",
          ["arn:aws:iam::aws:policy/AWSElasticBeanstalkWebTier", *extra_instance_policies])
    _role(svc_role, "elasticbeanstalk.amazonaws.com",
          ["arn:aws:iam::aws:policy/service-role/AWSElasticBeanstalkEnhancedHealth",
           "arn:aws:iam::aws:policy/AWSElasticBeanstalkManagedUpdatesCustomerRolePolicy"])
    iam.create_instance_profile(InstanceProfileName=profile)
    ctx.on_cleanup(lambda: iam.delete_instance_profile(InstanceProfileName=profile))
    iam.add_role_to_instance_profile(InstanceProfileName=profile, RoleName=ec2_role)
    ctx.on_cleanup(lambda: iam.remove_role_from_instance_profile(
        InstanceProfileName=profile, RoleName=ec2_role))
    return profile, svc_role


def _base_options(profile, service_role, single_instance=True):
    """The minimum option set for an environment; `t3.micro` is a deliberate literal."""
    return [
        {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "EnvironmentType",
         "Value": "SingleInstance" if single_instance else "LoadBalanced"},
        {"Namespace": "aws:autoscaling:launchconfiguration", "OptionName": "InstanceType",
         "Value": "t3.micro"},
        {"Namespace": "aws:autoscaling:launchconfiguration", "OptionName": "IamInstanceProfile",
         "Value": profile},
        {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "ServiceRole",
         "Value": service_role},
        {"Namespace": "aws:elasticbeanstalk:healthreporting:system", "OptionName": "SystemType",
         "Value": "enhanced"},
    ]


def _create_env(ctx, eb, **kwargs):
    """CreateEnvironment with a bounded retry over the IAM-propagation refusal, + LIFO teardown.

    IAM exposes no signal that a new principal is usable by another service, so a bounded retry
    that re-raises the refusal at its deadline replaces a sleep.
    """
    env_name = kwargs["EnvironmentName"]
    create_deadline_s = _budget_s(ctx, 300.0)
    deadline = time.monotonic() + create_deadline_s
    while True:
        try:
            resp = eb.create_environment(**kwargs)
            break
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            role_ish = "role" in str(exc).lower() or "permission" in str(exc).lower()
            if (code not in _IAM_PROPAGATION_CODES or not role_ish
                    or time.monotonic() >= deadline):
                if code in _IAM_PROPAGATION_CODES and role_ish and _budget_spent(ctx):
                    raise TimeoutError(f"CreateEnvironment {env_name} waiting for its IAM roles "
                                       f"to propagate: the run budget ended first; not "
                                       f"graded") from exc
                raise
            time.sleep(2.0)
    ctx.on_cleanup(lambda: _terminate(eb, env_name))
    return resp


def _terminate(eb, env_name):
    """Terminate and poll to Terminated. Registered via ctx.on_cleanup, so it runs LIFO.

    Routinely takes 180-420s; cutting it off leaks a live EC2 instance and Auto Scaling group.
    """
    terminate_deadline_s = 900.0
    try:
        eb.terminate_environment(EnvironmentName=env_name)
    except ClientError as exc:
        # Already terminating or already gone: both are the wanted state; anything else re-raises.
        if exc.response["Error"]["Code"] not in (
                "InvalidParameterValue", "ResourceNotFoundException"):
            raise
    _poll(lambda: (_describe_env(eb, env_name) or {}).get("Status"),
          lambda s: s is None or s == "Terminated",
          timeout_s=terminate_deadline_s, interval_s=15,
          what=f"environment {env_name} reaching Terminated")


def _publish_version(ctx, eb, s3, app, marker, nonce, extra=None, label_prefix="v-"):
    """Upload a source bundle and create a PROCESSED application version from it.

    Returns (version_label, bucket, key). The Processed wait is bounded and raises.
    """
    bucket = eb.create_storage_location()["S3Bucket"]
    label = ctx.unique_name(label_prefix)
    key = f"sim2real-eb/{app}/{label}.zip"
    s3.put_object(Bucket=bucket, Key=key, Body=_app_zip(nonce, extra),
                  Tagging=f"sim2real={marker}")
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=key))
    eb.create_application_version(
        ApplicationName=app, VersionLabel=label,
        SourceBundle={"S3Bucket": bucket, "S3Key": key}, Process=True,
        Tags=[{"Key": "sim2real", "Value": marker}])
    ctx.on_cleanup(lambda: eb.delete_application_version(
        ApplicationName=app, VersionLabel=label, DeleteSourceBundle=False))
    # Case-folded: real AWS answers "PROCESSING"/"PROCESSED" while the Smithy model declares
    # Processing/Processed.
    process_deadline_s = _budget_s(ctx, 300.0)
    status = _poll(
        lambda: eb.describe_application_versions(
            ApplicationName=app, VersionLabels=[label])["ApplicationVersions"][0]["Status"],
        lambda s: s.upper() != "PROCESSING",
        timeout_s=process_deadline_s, interval_s=1.0,
        what=f"application version {label} leaving Processing", ctx=ctx)
    assert status.upper() == "PROCESSED", (
        f"version {label!r} must process cleanly before it can be deployed; "
        f"DescribeApplicationVersions reports Status={status!r}")
    return label, bucket, key


def _ready(eb, env_name, what_suffix="", ready_deadline_s=1500.0, ctx=None):
    """Wait for the environment to settle Ready; the poll never ends on Terminated/Terminating."""
    env = _poll(lambda: _describe_env(eb, env_name),
                lambda e: e is not None and e.get("Status") == "Ready",
                timeout_s=ready_deadline_s, interval_s=2.0,
                what=f"environment {env_name} reaching Ready{what_suffix}", ctx=ctx)
    assert env["Status"] == "Ready", (
        f"settled Status must be exactly Ready, got {env['Status']!r}")
    return env


def _new_application(ctx, eb, prefix, marker):
    """Create the application, registering its delete first so LIFO teardown runs it after every
    environment terminate; the other order races a still-terminating environment and leaks it."""
    app = ctx.unique_name(prefix)
    eb.create_application(ApplicationName=app, Tags=[{"Key": "sim2real", "Value": marker}])
    ctx.on_cleanup(lambda: eb.delete_application(ApplicationName=app, TerminateEnvByForce=True))
    return app


@tags("axis:happy-path", "cap:c4", "concern:eventing", "dp:api", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """An environment update's event is delivered via the attached SNS topic to its SQS queue and
    names the environment; an unattached control topic's queue receives nothing but a direct
    publish sent after that notification, and that publish never crosses into the attached queue.

    Reference: https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/using-features.managing.sns.html
    """
    eb = ctx.client("elasticbeanstalk")
    s3 = ctx.client("s3")
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")
    sts = ctx.client("sts")
    account = sts.get_caller_identity()["Account"]
    marker = "eb-sns-notifications"
    nonce = ctx.unique_name("nonce-")
    ns = "aws:elasticbeanstalk:application:environment"
    sns_ns = "aws:elasticbeanstalk:sns:topics"
    v1 = ctx.unique_name("notify-before-")
    v2 = ctx.unique_name("notify-after-")
    tag = [{"Key": "sim2real", "Value": marker}]

    def _wire_topic_to_queue(kind):
        """A topic, a queue, a policy allowing exactly that topic, and a subscription."""
        topic = sns.create_topic(Name=ctx.unique_name(f"sim2real-eb-{kind}-topic-"),
                                 Tags=tag)["TopicArn"]
        ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic))
        queue = sqs.create_queue(QueueName=ctx.unique_name(f"sim2real-eb-{kind}-queue-"),
                                 tags={"sim2real": marker})["QueueUrl"]
        ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue))
        queue_arn = sqs.get_queue_attributes(
            QueueUrl=queue, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
        policy = {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "sns.amazonaws.com"},
            "Action": "sqs:SendMessage",
            "Resource": queue_arn,
            "Condition": {"ArnEquals": {"aws:SourceArn": topic}},
        }]}
        sqs.set_queue_attributes(QueueUrl=queue, Attributes={"Policy": json.dumps(policy)})
        sub = sns.subscribe(TopicArn=topic, Protocol="sqs", Endpoint=queue_arn,
                            ReturnSubscriptionArn=True)["SubscriptionArn"]
        ctx.on_cleanup(lambda: sns.unsubscribe(SubscriptionArn=sub))
        assert queue_arn.endswith(f":{account}:{queue.rsplit('/', 1)[-1]}"), (
            f"the queue ARN must belong to the calling account; got {queue_arn!r} for account "
            f"{account!r}")
        return topic, queue

    attached_topic, attached_queue = _wire_topic_to_queue("attached")
    control_topic, control_queue = _wire_topic_to_queue("control")

    def _drain(queue_url, seconds):
        """Long-poll for up to *seconds*, returning as soon as anything is seen."""
        bodies = []
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            wait_s = int(min(20.0, max(1.0, math.ceil(end - time.monotonic()))))
            resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10,
                                       WaitTimeSeconds=wait_s)
            for msg in resp.get("Messages", []):
                bodies.append(msg["Body"])
                sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            if bodies:
                return bodies
        return bodies

    def _purge(queue_url, seconds):
        """Drain until a poll comes back empty or the deadline expires. Bounded; raises nothing."""
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10,
                                       WaitTimeSeconds=2)
            msgs = resp.get("Messages", [])
            if not msgs:
                return
            for msg in msgs:
                sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])

    # A calibration publish proves the control wiring is live before the environment exists.
    calib_token = ctx.unique_name("calibration-")
    sns.publish(TopicArn=control_topic, Subject="sim2real-calibration", Message=calib_token)
    calib = _poll(lambda: _drain(control_queue, 25), lambda b: bool(b),
                  timeout_s=_budget_s(ctx, 180.0), interval_s=1.0,
                  what=(f"the calibration publish reaching the control queue {control_queue!r}, "
                        f"which establishes that the wiring works"), ctx=ctx)
    assert any(json.loads(b).get("Message") == calib_token for b in calib), (
        f"the calibration publish must arrive verbatim; the control queue returned "
        f"{[json.loads(b).get('Message') for b in calib]!r}, expected {calib_token!r}")
    _purge(control_queue, 30)

    app = _new_application(ctx, eb, "sim2real-eb-sns-app-", marker)
    label, _bucket, _key = _publish_version(ctx, eb, s3, app, marker, nonce)

    env = ctx.unique_name("sim2real-eb-sns-env-")
    profile, role = _eb_iam(ctx, marker)
    _create_env(
        ctx, eb, ApplicationName=app, EnvironmentName=env, VersionLabel=label,
        CNAMEPrefix=env, SolutionStackName=_solution_stack(eb),
        OptionSettings=_base_options(profile, role) + [
            {"Namespace": ns, "OptionName": "SIM2REAL_EB_NOTIFY", "Value": v1},
            {"Namespace": sns_ns, "OptionName": "Notification Topic ARN",
             "Value": attached_topic},
        ],
        Tags=tag)
    _ready(eb, env, ready_deadline_s=_budget_s(ctx, 1500.0), ctx=ctx)

    cfg = eb.describe_configuration_settings(ApplicationName=app, EnvironmentName=env)
    opts = cfg["ConfigurationSettings"][0]["OptionSettings"]
    wired = [o for o in opts
             if o.get("Namespace") == sns_ns and o.get("OptionName") == "Notification Topic ARN"]
    assert len(wired) == 1 and wired[0].get("Value") == attached_topic, (
        f"the environment must be wired to the topic this check created before any delivery claim "
        f"is made; DescribeConfigurationSettings reported {wired!r}, expected exactly one entry "
        f"with Value {attached_topic!r}")

    # Clear anything the environment launch itself already published, so the message asserted
    # below is attributable to the update that follows and to nothing earlier.
    _purge(attached_queue, 60)

    upd = eb.update_environment(
        EnvironmentName=env,
        OptionSettings=[{"Namespace": ns, "OptionName": "SIM2REAL_EB_NOTIFY", "Value": v2}])
    assert upd["EnvironmentName"] == env, (
        f"UpdateEnvironment must answer for the environment it was given, {env!r}; it named "
        f"{upd.get('EnvironmentName')!r}")
    assert upd["Status"] == "Updating", (
        f"the option change must move the environment to Updating, got {upd['Status']!r}")
    _poll(lambda: (_describe_env(eb, env) or {}).get("Status"), lambda s: s == "Ready",
          timeout_s=_budget_s(ctx, 1500.0), interval_s=2.0,
          what=f"environment {env} settling Ready after the notified update", ctx=ctx)

    delivered = _poll(lambda: _drain(attached_queue, 25), lambda b: bool(b),
                      timeout_s=_budget_s(ctx, 600.0), interval_s=1.0,
                      what=(f"an environment notification for {env} arriving in the SQS queue "
                            f"subscribed to {attached_topic!r}"), ctx=ctx)
    envelopes = [json.loads(b) for b in delivered]
    assert all(e.get("TopicArn") == attached_topic for e in envelopes), (
        f"every delivered notification must come from the attached topic {attached_topic!r}; the "
        f"envelopes reported {[e.get('TopicArn') for e in envelopes]!r}")
    naming = [e for e in envelopes
              if env in (e.get("Message") or "") or env in (e.get("Subject") or "")]
    assert naming, (
        f"a delivered environment notification must name the environment it is about. None of "
        f"the {len(envelopes)} messages mentioned {env!r}; subjects were "
        f"{[e.get('Subject') for e in envelopes]!r} and the first message was "
        f"{(envelopes[0].get('Message') or '')[:200]!r}")

    # Absence by contrast: a direct publish to the control topic, made after Beanstalk published
    # the update's notification, must be the only message the control queue receives.
    repair_token = ctx.unique_name("control-is-live-")
    sns.publish(TopicArn=control_topic, Subject="sim2real-control",
                Message=repair_token)
    on_control: list[str] = []

    def _until_token(queue_url, seen):
        seen.extend(_drain(queue_url, 25))
        return [json.loads(b).get("Message") for b in seen]

    _poll(lambda: _until_token(control_queue, on_control),
          lambda msgs: repair_token in msgs,
          timeout_s=_budget_s(ctx, 120.0), interval_s=1.0,
          what=(f"the control queue receiving a DIRECT publish to {control_topic!r}, "
                f"which proves the absence below was Beanstalk's choice and not a "
                f"broken subscription"), ctx=ctx)
    stray = [b for b in on_control if json.loads(b).get("Message") != repair_token]
    assert stray == [], (
        f"Beanstalk must publish this environment's events ONLY to the topic it was given: the "
        f"control queue, on a topic never attached to {env}, received {stray!r} before the direct "
        f"publish sent after the attached notification arrived")
    depth = sqs.get_queue_attributes(
        QueueUrl=control_queue,
        AttributeNames=["ApproximateNumberOfMessages",
                        "ApproximateNumberOfMessagesNotVisible"])["Attributes"]
    assert depth["ApproximateNumberOfMessages"] == "0", (
        f"the second observable on the control queue must agree it is empty; it reports "
        f"ApproximateNumberOfMessages={depth['ApproximateNumberOfMessages']!r}")
    assert depth["ApproximateNumberOfMessagesNotVisible"] == "0", (
        f"the control queue must have nothing in flight either; it reports "
        f"ApproximateNumberOfMessagesNotVisible="
        f"{depth['ApproximateNumberOfMessagesNotVisible']!r}")

    # The two wirings are independent: the control-only publish must not reach the attached queue.
    # A publish to the attached topic made after it is the positive control.
    attached_token = ctx.unique_name("attached-is-live-")
    sns.publish(TopicArn=attached_topic, Subject="sim2real-control", Message=attached_token)
    on_attached: list[str] = []
    crossed = _poll(lambda: _until_token(attached_queue, on_attached),
                    lambda msgs: attached_token in msgs,
                    timeout_s=_budget_s(ctx, 120.0), interval_s=1.0,
                    what=f"the attached queue receiving a DIRECT publish to {attached_topic!r}",
                    ctx=ctx)
    assert repair_token not in crossed, (
        f"a publish to the control topic must never reach the queue subscribed to the ATTACHED "
        f"topic — otherwise the environment notification asserted above could have been anything "
        f"landing in any queue. The attached queue received {crossed!r}, which includes "
        f"{repair_token!r}")

if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
