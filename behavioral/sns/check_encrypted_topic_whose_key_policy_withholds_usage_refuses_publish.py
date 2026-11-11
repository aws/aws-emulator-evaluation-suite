"""encrypted-topic-whose-key-policy-withholds-usage-refuses-publish."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "encrypted-topic-whose-key-policy-withholds-usage-refuses-publish"
GROUP = "authorization"
SERVICES = ["sns"]

_ADMIN_ONLY = [
    "kms:Create*", "kms:Describe*", "kms:Enable*", "kms:List*", "kms:Put*", "kms:Update*",
    "kms:Revoke*", "kms:Disable*", "kms:Get*", "kms:Delete*", "kms:TagResource",
    "kms:UntagResource", "kms:ScheduleKeyDeletion", "kms:CancelKeyDeletion",
]


def _error(fn):
    """(code, message) of the ClientError ``fn`` raises; an unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Publish to an SSE-KMS topic is refused KMSAccessDenied when the key policy grants only
    admin actions, while a twin topic whose key delegates to IAM accepts it; granting usage in
    the key policy makes the same Publish succeed, with no IAM-side change.
    """
    sns = ctx.client("sns")
    kms = ctx.client("kms")
    partition = ctx.client("sts").get_caller_identity()["Arn"].split(":")[1]
    root = f"arn:{partition}:iam::{ctx.account}:root"

    delegating_key = _create_key(ctx, [{
        "Sid": "AccountAdministersAndUses", "Effect": "Allow", "Principal": {"AWS": root},
        "Action": "kms:*", "Resource": "*",
    }])
    admin_only = [{
        "Sid": "AccountAdministersOnly", "Effect": "Allow", "Principal": {"AWS": root},
        "Action": _ADMIN_ONLY, "Resource": "*",
    }]
    withheld_key = _create_key(ctx, admin_only)

    control_topic = _create_topic(ctx, "sim2real-behav-sns-kmsok-", delegating_key)
    withheld_topic = _create_topic(ctx, "sim2real-behav-sns-kmsno-", withheld_key)

    role_name, role_arn = _create_publisher_role(ctx, partition, [control_topic, withheld_topic])
    session = "sim2real-sns-kmspub"
    role_sns = _client_as_role(ctx, "sns", role_arn, session)

    mid = _until_published(role_sns, control_topic)
    assert mid, "control: the role's Publish to the topic whose key delegates to IAM must succeed"

    code, message = _error(lambda: role_sns.publish(TopicArn=withheld_topic, Message="sim2real-withheld"))
    key_arn = kms.describe_key(KeyId=withheld_key)["KeyMetadata"]["Arn"]
    assumed = f"arn:{partition}:sts::{ctx.account}:assumed-role/{role_name}/{session}"
    expected = _relayed(
        f"User: {assumed} is not authorized to perform: kms:GenerateDataKey on resource: "
        f"{key_arn} because no resource-based policy allows the kms:GenerateDataKey action",
        "AccessDeniedException", message)
    assert (code, message) == ("KMSAccessDenied", expected), (
        "Publish to a topic whose key policy grants no usage must be refused with "
        f"KMSAccessDenied {expected!r}; got {code!r} {message!r}"
    )
    again = role_sns.publish(TopicArn=control_topic, Message="sim2real-control-again")["MessageId"]
    assert again, "control: the twin topic must keep accepting the same role's Publish"

    usage = admin_only + [{
        "Sid": "AccountUses", "Effect": "Allow", "Principal": {"AWS": root},
        "Action": ["kms:GenerateDataKey*", "kms:Decrypt"], "Resource": "*",
    }]
    kms.put_key_policy(KeyId=withheld_key, PolicyName="default",
                       Policy=json.dumps({"Version": "2012-10-17", "Statement": usage}))
    mid = _until_published(role_sns, withheld_topic, retry_code="KMSAccessDenied")
    assert mid, "once the key policy grants usage, the identical Publish must return a MessageId"


def _relayed(text: str, kms_code: str, actual: str | None) -> str:
    """The exact message SNS relays from KMS. The KMS request id is the only per-call token;
    it is taken from the actual text and must parse as a UUID."""
    _, _, tail = (actual or "").partition("; Request ID: ")
    request_id = tail[:36]
    try:
        uuid.UUID(request_id)
    except ValueError:
        request_id = "<a KMS request id>"
    return (f"{text} (Service: AWSKMS; Status Code: 400; Error Code: {kms_code}; "
            f"Request ID: {request_id}; Proxy: null)")


def _create_key(ctx, statements: list[dict]) -> str:
    kms = ctx.client("kms")
    key_id = kms.create_key(
        Description=f"sim2real-behav-sns {CHECK}",
        Policy=json.dumps({"Version": "2012-10-17", "Statement": statements}),
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))
    return key_id


def _create_topic(ctx, prefix: str, key_id: str) -> str:
    sns = ctx.client("sns")
    arn = sns.create_topic(Name=ctx.unique_name(prefix), Attributes={"KmsMasterKeyId": key_id},
                           Tags=[{"Key": "sim2real", "Value": CHECK}])["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=arn))
    return arn


def _create_publisher_role(ctx, partition: str, topics: list[str]) -> tuple[str, str]:
    """A role allowed sns:Publish on ``topics`` and the KMS data-key actions on any key."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-sns-r-")
    trust = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"AWS": f"arn:{partition}:iam::{ctx.account}:root"},
        "Action": "sts:AssumeRole"}]}
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
                          Tags=[{"Key": "sim2real", "Value": CHECK}])["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.put_role_policy(RoleName=name, PolicyName="publish", PolicyDocument=json.dumps({
        "Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": "sns:Publish", "Resource": topics},
            {"Effect": "Allow", "Action": ["kms:GenerateDataKey*", "kms:Decrypt"], "Resource": "*"},
        ]}))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="publish"))
    return name, arn


def _client_as_role(ctx, service: str, role_arn: str, session: str):
    """A client signed by an assumed session of ``role_arn``; retries only while IAM has not
    yet propagated the new role's trust policy."""
    sts = ctx.client("sts")
    deadline = time.monotonic() + 90
    while True:
        try:
            creds = sts.assume_role(RoleArn=role_arn, RoleSessionName=session)["Credentials"]
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDenied" or time.monotonic() > deadline:
                raise
            time.sleep(3)
    return ctx.client(service, creds={
        "aws_access_key_id": creds["AccessKeyId"],
        "aws_secret_access_key": creds["SecretAccessKey"],
        "aws_session_token": creds["SessionToken"],
    })


def _until_published(role_sns, topic_arn: str, retry_code: str = "AuthorizationError") -> str:
    """Publish as the role, retrying ``retry_code`` (and only it) while a just-written grant
    propagates; a grant that never takes effect fails loudly."""
    deadline = time.monotonic() + 120
    while True:
        try:
            return role_sns.publish(TopicArn=topic_arn, Message="sim2real-probe")["MessageId"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != retry_code or time.monotonic() > deadline:
                raise
            time.sleep(3)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
