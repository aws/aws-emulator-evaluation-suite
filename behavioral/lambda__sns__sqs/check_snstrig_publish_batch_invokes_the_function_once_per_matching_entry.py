"""snstrig-publish-batch-invokes-the-function-once-per-matching-entry."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "snstrig-publish-batch-invokes-the-function-once-per-matching-entry"
GROUP = "sns-trigger-delivery"
SERVICES = ["lambda", "sns", "sqs"]

#: SNS-to-Lambda delivery is normally seconds; bounded for a first delivery racing the fresh grant.
_DELIVERY_DEADLINE_S = 180.0


@tags("axis:negative-delivery", "cap:c3", "concern:data-plane", "concern:eventing", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A PublishBatch to a topic with a filtered Lambda subscription invokes the function once
    per matching entry, each a one-record aws:sns event with that entry's own Message, MessageId
    and MessageAttributes, and never for the entry the filter rejects."""
    sns = ctx.client("sns")
    tok = ctx.unique_name(_PREFIX)
    sink_url, sink_arn = _sink(ctx, f"{tok}-sink")
    fn = f"{tok}-fn"
    fn_arn = _forwarder(ctx, fn, f"{tok}-role", sink_url, sink_arn)
    topic = sns.create_topic(Name=f"{tok}-topic",
                             Tags=[{"Key": "sim2real", "Value": CHECK}])["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic))
    _grant(ctx, fn, topic)
    sub = sns.subscribe(TopicArn=topic, Protocol="lambda", Endpoint=fn_arn,
                        ReturnSubscriptionArn=True,
                        Attributes={"FilterPolicy": json.dumps({"kind": ["order", "refund"]})}
                        )["SubscriptionArn"]
    ctx.on_cleanup(lambda: sns.unsubscribe(SubscriptionArn=sub))

    rounds: dict[str, dict[str, dict]] = {}
    forwarded: list[dict] = []
    graded = None
    deadline = time.monotonic() + _DELIVERY_DEADLINE_S
    started = time.monotonic()
    # Each round publishes a fresh batch: a batch that races the new invoke grant can be lost.
    while graded is None:
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"no round's matching entries all reached the function within "
                f"{_DELIVERY_DEADLINE_S}s across {len(rounds)} batches; "
                f"{len(forwarded)} invocations forwarded")
        rnd = ctx.unique_name("r-")
        entries = {
            "order": {"Id": "order", "Message": f"{rnd}-order",
                      "MessageAttributes": {"kind": {"DataType": "String", "StringValue": "order"},
                                            "channel": {"DataType": "String", "StringValue": "web"}}},
            "refund": {"Id": "refund", "Message": f"{rnd}-refund",
                       "MessageAttributes": {"kind": {"DataType": "String", "StringValue": "refund"}}},
            "noise": {"Id": "noise", "Message": f"{rnd}-noise",
                      "MessageAttributes": {"kind": {"DataType": "String", "StringValue": "noise"}}},
        }
        resp = sns.publish_batch(TopicArn=topic, PublishBatchRequestEntries=list(entries.values()))
        assert resp.get("Failed", []) == [] and len(resp.get("Successful", [])) == 3, (
            f"PublishBatch must accept all three entries, got Failed {resp.get('Failed')!r}"
        )
        ids = {e["Id"]: e["MessageId"] for e in resp["Successful"]}
        rounds[rnd] = {k: {**v, "MessageId": ids[k]} for k, v in entries.items()}
        forwarded += _drain(ctx, sink_url, 15)
        for r, ents in rounds.items():
            messages = [rec["Sns"].get("Message") for _f, rec in _records(forwarded)]
            if ents["order"]["Message"] in messages and ents["refund"]["Message"] in messages:
                graded = r
                break
    # The rejected entry must stay absent over a window scaled from the observed delivery latency.
    latency = max(time.monotonic() - started, 1.0)
    forwarded += _drain(ctx, sink_url, max(2.0 * latency, 30.0))

    ents = rounds[graded]
    mine = [f for f in forwarded
            if any(rec["Sns"].get("Message", "").startswith(graded) for rec in f["event"]["Records"])]
    assert all(len(f["event"]["Records"]) == 1 for f in mine), (
        f"each batch entry must be its own one-record invocation, got record counts "
        f"{[len(f['event']['Records']) for f in mine]!r}"
    )
    by_message = {f["event"]["Records"][0]["Sns"]["Message"]: f for f in mine}
    assert sorted(by_message) == sorted([ents["order"]["Message"], ents["refund"]["Message"]]), (
        f"the graded batch must invoke the function for exactly its two matching entries; "
        f"invocations carried {sorted(by_message)!r}"
    )
    assert len(mine) == 2, f"expected two invocations for the graded batch, got {len(mine)}"
    for key in ("order", "refund"):
        fwd = by_message[ents[key]["Message"]]
        rec = fwd["event"]["Records"][0]
        assert (fwd["fn"], rec.get("EventSource"), rec.get("EventSubscriptionArn") == sub) == (
            fn, "aws:sns", True), (
            f"the {key} entry must invoke the subscribed function through this subscription; "
            f"function {fwd['fn']!r}, EventSource {rec.get('EventSource')!r}"
        )
        want_attrs = {name: {"Type": v["DataType"], "Value": v["StringValue"]}
                      for name, v in ents[key]["MessageAttributes"].items()}
        have = {k: rec["Sns"].get(k) for k in ("TopicArn", "MessageId", "MessageAttributes")}
        assert have == {"TopicArn": topic, "MessageId": ents[key]["MessageId"],
                        "MessageAttributes": want_attrs}, (
            f"the {key} record must carry its own entry's MessageId and attributes; got "
            f"attributes {have['MessageAttributes']!r}, MessageId matches="
            f"{have['MessageId'] == ents[key]['MessageId']}"
        )


_PREFIX = "sim2real-xsvc-snsbatch-"

_NOOP_HANDLER = "def handler(event, context):\n    return None\n"

#: The function under test forwards what it was invoked with — the whole SNS event, plus which
#: function and which qualified ARN ran — to an SQS sink the check reads. Its role grants ONLY
#: sqs:SendMessage on that queue and nothing in logs:*, so an invocation cannot create a
#: /aws/lambda/<fn> log group, which delete_function would not remove and which would outlive the check.
_FORWARDER = (
    "import json, os, boto3\n"
    "_SQS = boto3.client('sqs')\n"
    "def handler(event, context):\n"
    "    _SQS.send_message(QueueUrl=os.environ['SINK_URL'], MessageBody=json.dumps({\n"
    "        'fn': context.function_name, 'invoked': context.invoked_function_arn,\n"
    "        'event': event}))\n"
)

#: Bound on the one refusal a fresh role produces: "The role defined for the function cannot be
#: assumed by Lambda". Retried as that specific error, never slept past.
_ROLE_ASSUME_DEADLINE_S = 90.0


def _poll(probe, predicate, *, timeout_s=60.0, interval_s=2.0, description="condition"):
    """Poll probe() until predicate(result) holds; return the result, or fail naming the last one."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _role(ctx, name: str, statements: list | None = None) -> str:
    """A Lambda execution role, deleted (inline policies first) at teardown. Returns its ARN."""
    iam = ctx.client("iam")
    trust = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
        "Action": "sts:AssumeRole"}]}
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, name))
    if statements:
        iam.put_role_policy(RoleName=name, PolicyName="inline", PolicyDocument=json.dumps(
            {"Version": "2012-10-17", "Statement": statements}))
    return arn


def _delete_role(ctx, name: str) -> None:
    iam = ctx.client("iam")
    try:
        for policy in iam.list_role_policies(RoleName=name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=name, PolicyName=policy)
        iam.delete_role(RoleName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _function(ctx, name: str, role_arn: str, code: str = _NOOP_HANDLER,
              env: dict | None = None) -> str:
    """Create a python3.12 function, retrying ONLY the fresh-role refusal, then wait for Active."""
    lam = ctx.client("lambda")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", code)
    kwargs = {"FunctionName": name, "Runtime": "python3.12", "Role": role_arn,
              "Handler": "index.handler", "Code": {"ZipFile": buf.getvalue()}, "Timeout": 30}
    if env:
        kwargs["Environment"] = {"Variables": env}
    deadline = time.monotonic() + _ROLE_ASSUME_DEADLINE_S
    while True:
        try:
            arn = lam.create_function(**kwargs)["FunctionArn"]
            break
        except ClientError as exc:
            if "cannot be assumed" not in str(exc) or time.monotonic() > deadline:
                raise
            time.sleep(2)
    ctx.on_cleanup(lambda: _delete_function(ctx, name))
    state = _poll(lambda: lam.get_function_configuration(FunctionName=name)["State"],
                  lambda s: s != "Pending", timeout_s=120.0,
                  description=f"function {name} leaves Pending")
    assert state == "Active", f"function {name} settled in state {state!r}, expected 'Active'"
    return arn


def _delete_function(ctx, name: str) -> None:
    try:
        ctx.client("lambda").delete_function(FunctionName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _subscribe(ctx, topic_arn: str, endpoint: str) -> str:
    """Subscribe a Lambda endpoint; the teardown unsubscribes (Unsubscribe is idempotent)."""
    sns = ctx.client("sns")
    arn = sns.subscribe(TopicArn=topic_arn, Protocol="lambda", Endpoint=endpoint,
                        ReturnSubscriptionArn=True)["SubscriptionArn"]
    ctx.on_cleanup(lambda: sns.unsubscribe(SubscriptionArn=arn))
    return arn


def _grant(ctx, function: str, topic_arn: str, sid: str = "sns-invoke") -> None:
    """The resource-policy half of an SNS trigger. Deleted with the function, so no teardown."""
    ctx.client("lambda").add_permission(
        FunctionName=function, StatementId=sid, Action="lambda:InvokeFunction",
        Principal="sns.amazonaws.com", SourceArn=topic_arn)


def _sink(ctx, name: str) -> tuple[str, str]:
    """An SQS queue the forwarder writes to. Returns (url, arn); deleted at teardown."""
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=name)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _forwarder(ctx, name: str, role_name: str, sink_url: str, sink_arn: str) -> str:
    """A function that forwards each invocation to the sink; its role can do nothing else."""
    role = _role(ctx, role_name, [{"Effect": "Allow", "Action": "sqs:SendMessage",
                                   "Resource": sink_arn}])
    return _function(ctx, name, role, code=_FORWARDER, env={"SINK_URL": sink_url})


def _drain(ctx, url: str, seconds: float) -> list[dict]:
    """Receive (and delete) everything the sink holds for up to `seconds`; parsed forwarder bodies."""
    sqs = ctx.client("sqs")
    out: list[dict] = []
    deadline = time.monotonic() + seconds
    while True:
        wait = int(max(0, min(10, deadline - time.monotonic())))
        msgs = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10,
                                   WaitTimeSeconds=wait).get("Messages") or []
        for m in msgs:
            out.append(json.loads(m["Body"]))
            sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])
        if time.monotonic() >= deadline:
            return out


def _records(forwarded: list[dict]) -> list[tuple[dict, dict]]:
    """(forwarder body, SNS record) for every record of every forwarded invocation."""
    return [(f, r) for f in forwarded for r in (f.get("event") or {}).get("Records") or []]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
