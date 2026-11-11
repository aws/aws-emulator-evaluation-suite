"""rule-s3-action-substitution-template-computes-the-object-key."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "rule-s3-action-substitution-template-computes-the-object-key"
GROUP = "rule-invocation"
SERVICES = ["iot", "s3"]

# ${timestamp()} is deliberately not used: the docs do not settle its unit (seconds vs ms).
_KEY_TEMPLATE = "${topic()}/${deviceId}.json"
_DELIVERY_DEADLINE_S = 180.0


@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:data-plane",
    "concern:e2e",
    "concern:eventing",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A rule's S3 action key "${topic()}/${deviceId}.json" resolves the topic and a payload field,
    so the bucket holds exactly that one key, and the object carries the SELECT's level2 column.

    Reference: https://docs.aws.amazon.com/iot/latest/developerguide/s3-rule-action.html
    Reference: https://docs.aws.amazon.com/iot/latest/developerguide/iot-substitution-templates.html
    """
    iot = ctx.client("iot")
    data = ctx.client("iot-data")
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    from botocore.exceptions import ClientError

    scenario = "iot-rule-s3-substitution-template"
    account = ctx.client("sts").get_caller_identity()["Account"]

    bucket = ctx.unique_name("sim2real-iot-s3sub-").lower()
    create_kwargs = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        # us-east-1 is the one region CreateBucket rejects an explicit LocationConstraint for.
        create_kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**create_kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": scenario}]})

    role_name = ctx.unique_name("sim2real-iot-s3role-")
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Service": "iot.amazonaws.com"},
                "Action": "sts:AssumeRole",
                "Condition": {"StringEquals": {"aws:SourceAccount": account}},
            }],
        }),
        Tags=[{"Key": "sim2real", "Value": scenario}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    inline = "sim2real-put-object"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=inline,
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["s3:PutObject"],
                "Resource": f"arn:aws:s3:::{bucket}/*",
            }],
        }),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=inline))

    base = f"sim2real/{ctx.unique_name('sub')}"
    topic = f"{base}/sensors"
    device_id = ctx.unique_name("dev")
    expected_key = f"{topic}/{device_id}.json"

    rule_name = ctx.unique_name("sim2real_iot_s3sub_").replace("-", "_")
    _retry_client_error(
        lambda: iot.create_topic_rule(
            ruleName=rule_name,
            topicRulePayload={
                "sql": f"SELECT *, topic(2) AS level2 FROM '{base}/+'",
                "awsIotSqlVersion": "2016-03-23",
                "ruleDisabled": False,
                "description": "sim2real substitution-template key",
                "actions": [{
                    "s3": {"bucketName": bucket, "key": _KEY_TEMPLATE, "roleArn": role_arn},
                }],
            },
            tags=f"sim2real={scenario}",
        ),
        what="CreateTopicRule never accepted the freshly created S3 role",
    )
    ctx.on_cleanup(lambda: iot.delete_topic_rule(ruleName=rule_name))

    stored = iot.get_topic_rule(ruleName=rule_name)["rule"]
    assert stored["actions"][0]["s3"]["key"] == _KEY_TEMPLATE, (
        f"the rule stored the S3 key as {stored['actions'][0]['s3'].get('key')!r}, expected the "
        f"unexpanded template {_KEY_TEMPLATE!r} — the template must be resolved at DELIVERY time, "
        "not at rule-creation time"
    )

    payload = {"deviceId": device_id, "temp": 42, "marker": ctx.unique_name("m-")}
    body = json.dumps(payload).encode()

    # Rule creation is eventually consistent, so republish on a bounded deadline until the object
    # appears. Every attempt uses the identical topic and payload, so the derived key never varies and
    # repeated deliveries overwrite one object instead of accumulating several.
    deadline = time.monotonic() + _DELIVERY_DEADLINE_S
    head = None
    attempts = 0
    while time.monotonic() < deadline:
        attempts += 1
        # An HTTPS Publish reaches the rules engine like an MQTT publish; no certificate needed.
        data.publish(topic=topic, qos=1, payload=body)
        inner = time.monotonic() + 20
        while time.monotonic() < inner:
            try:
                head = s3.head_object(Bucket=bucket, Key=expected_key)
                break
            except ClientError as err:
                if err.response["Error"]["Code"] not in ("404", "NoSuchKey", "NotFound"):
                    raise
                time.sleep(2)
        if head is not None:
            break
    if head is None:
        listing = s3.list_objects_v2(Bucket=bucket)
        raise AssertionError(
            f"no object appeared at the substituted key {expected_key!r} in {bucket!r} after "
            f"{attempts!r} publishes over {_DELIVERY_DEADLINE_S}s; the bucket held "
            f"{[o['Key'] for o in listing.get('Contents', [])]!r} — a literal "
            f"{_KEY_TEMPLATE!r} there means the template was never resolved"
        )

    # the exact key set, not merely a hit, catches a literal or half-resolved template
    keys = {o["Key"] for o in s3.list_objects_v2(Bucket=bucket).get("Contents", [])}
    assert keys == {expected_key}, (
        f"the bucket held the key set {sorted(keys)!r}, expected exactly {[expected_key]!r}: "
        f"${{topic()}} must expand to {topic!r} and ${{deviceId}} to the payload's "
        f"{device_id!r}"
    )
    assert _KEY_TEMPLATE not in keys, (
        f"the object was stored under the LITERAL template {_KEY_TEMPLATE!r}; substitution "
        "templates in a rule action's key must be evaluated against the delivered message"
    )

    raw = s3.get_object(Bucket=bucket, Key=expected_key)["Body"].read()
    assert head["ContentLength"] == len(raw), (
        f"head_object reported ContentLength {head.get('ContentLength')!r} but get_object returned "
        f"{len(raw)!r} bytes for {expected_key!r}"
    )
    got = json.loads(raw)
    for field, value in payload.items():
        assert got.get(field) == value, (
            f"the stored document's {field!r} was {got.get(field)!r}, expected {value!r}; "
            "`SELECT *` must carry every original payload field through"
        )
    expected_level2 = topic.split("/")[1]
    assert got["level2"] == expected_level2, (
        f"the stored document's computed level2 column was {got.get('level2')!r}, expected "
        f"{expected_level2!r} — AWS IoT SQL's `topic(n)` is 1-indexed from the first segment, so "
        f"`topic(2)` on the publish topic {topic!r} is its SECOND segment, not its last; without it "
        "the SELECT's projection was not evaluated at all"
    )


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    """Teardown only, scoped to the bucket THIS check created — never a prefix sweep."""
    from botocore.exceptions import ClientError
    try:
        token = None
        while True:
            kwargs = {"Bucket": bucket}
            if token:
                kwargs["ContinuationToken"] = token
            page = s3.list_objects_v2(**kwargs)
            objects = [{"Key": o["Key"]} for o in page.get("Contents", [])]
            if objects:
                failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objects}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
            token = page.get("NextContinuationToken")
            if not token:
                break
        s3.delete_bucket(Bucket=bucket)
    except ClientError as err:
        if err.response["Error"]["Code"] not in ("NoSuchBucket", "404"):
            raise


def _retry_client_error(fn, *, what: str, attempts: int = 10, interval_s: float = 5.0):
    """Bounded retry over IAM propagation; RAISES the last error rather than swallowing it."""
    from botocore.exceptions import ClientError
    last = None
    for _ in range(attempts):
        try:
            return fn()
        except ClientError as err:
            last = err
            time.sleep(interval_s)
    raise AssertionError(f"{what}: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
