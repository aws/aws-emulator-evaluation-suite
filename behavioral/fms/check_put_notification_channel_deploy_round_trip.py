"""put-notification-channel-deploy-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "put-notification-channel-deploy-round-trip"
GROUP = "resource-lifecycle"
SERVICES = ["fms"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """With no Firewall Manager admin, PutNotificationChannel and GetNotificationChannel fail with AccessDeniedException
    "No default admin could be found for account <id> in Region <region>"; where Put succeeds,
    Get returns its topic and role and, after DeleteNotificationChannel, ResourceNotFoundException."""
    fms = ctx.client("fms")
    sns = ctx.client("sns")
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    sts.get_caller_identity()["Account"]

    topic_name = ctx.unique_name("sim2real-fms-notif")
    topic_arn = sns.create_topic(
        Name=topic_name, Tags=[{"Key": "sim2real", "Value": CHECK}]
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))

    role_name = ctx.unique_name("sim2real-fms-notif-role")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "fms.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    import json

    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    publish_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "sns:Publish", "Resource": topic_arn}],
    }
    policy_name = "sim2real-fms-notif-publish"
    iam.put_role_policy(
        RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(publish_policy)
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))

    from botocore.exceptions import ClientError

    no_admin = f"No default admin could be found for account {ctx.account} in Region {ctx.region}"
    try:
        # Despite its name, SnsRoleName's shape is documented as the IAM role's ARN.
        fms.put_notification_channel(SnsTopicArn=topic_arn, SnsRoleName=role_arn)
        put_error = None
    except ClientError as e:
        put_error = e.response["Error"]

    if put_error is not None:
        # Channel configuration is gated behind the same authorization check as
        # resource sets / apps lists / protocols lists for this unconfigured account.
        put_code, put_message = put_error["Code"], put_error.get("Message", "")
        assert put_code == "AccessDeniedException", f"expected AccessDeniedException, got {put_code}"
        assert put_message == no_admin, f"unexpected AccessDeniedException message: {put_message!r}"
        get_code, get_message = _client_error(lambda: fms.get_notification_channel())
        assert get_code == "AccessDeniedException", (
            f"PutNotificationChannel was rejected, so GetNotificationChannel should "
            f"consistently be gated the same way, got {get_code}"
        )
        assert get_message == no_admin, f"unexpected AccessDeniedException message: {get_message!r}"
        return

    ctx.on_cleanup(_delete_channel_tolerant(fms))

    # Put succeeded: verify the real round-trip through Get, then Delete, then Get again.
    def _channel_matches():
        try:
            resp = fms.get_notification_channel()
        except ClientError:
            return False
        return resp.get("SnsTopicArn") == topic_arn and resp.get("SnsRoleName") == role_arn

    assert _poll(_channel_matches, timeout_s=30), "GetNotificationChannel never reflected the Put"

    fms.delete_notification_channel()

    def _channel_gone():
        try:
            fms.get_notification_channel()
        except ClientError as e:
            return e.response["Error"]["Code"] == "ResourceNotFoundException"
        return False

    assert _poll(_channel_gone, timeout_s=30), (
        "GetNotificationChannel must report ResourceNotFoundException after DeleteNotificationChannel"
    )


def _client_error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING a call real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        err = e.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _delete_channel_tolerant(fms):
    def _delete():
        from botocore.exceptions import ClientError

        try:
            fms.delete_notification_channel()
        except ClientError as e:
            if e.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    return _delete


def _poll(predicate, timeout_s: float, interval_s: float = 2.0) -> bool:
    import time

    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(interval_s)
    return predicate()


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
