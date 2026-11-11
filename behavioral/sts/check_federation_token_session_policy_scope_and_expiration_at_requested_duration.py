"""federation-token-session-policy-scope-and-expiration-at-requested-duration."""
from __future__ import annotations

import email.utils
import json
import time

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "federation-token-session-policy-scope-and-expiration-at-requested-duration"
GROUP = "e2e"
SERVICES = ["sts"]

#: GetFederationToken DurationSeconds floor.
_MIN_DURATION_S = 900
#: Client/server skew and request latency on a clock-based bound.
_TOLERANCE_S = 120


def _client_error(fn):
    """The (code, message) of the ClientError ``fn`` raises; an unexpected success fails loudly."""
    try:
        fn()
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("the call succeeded where AWS refuses it")


def _server_time(response):
    """AWS's own clock when it produced ``response``, from the HTTP Date header."""
    raw = response.get("ResponseMetadata", {}).get("HTTPHeaders", {}).get("date")
    assert raw, "the GetFederationToken response carried no Date header"
    return email.utils.parsedate_to_datetime(raw)


def _delete_bucket_if_exists(s3, bucket_name) -> None:
    try:
        s3.delete_bucket(Bucket=bucket_name)
    except ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _gone_ok(fn) -> None:
    try:
        fn()
    except ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _client_from_creds(ctx, service, creds):
    return ctx.client(
        service,
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )


def _iam_user_creds(ctx, policy):
    """A fresh IAM user's long-term access key (``creds`` for ctx.client); GetFederationToken
    requires an IAM user's long-term credentials."""
    iam = ctx.client("iam")
    user_name = ctx.unique_name("sim2real-behav-stsuser-")
    iam.create_user(UserName=user_name, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: _gone_ok(lambda: iam.delete_user(UserName=user_name)))
    iam.put_user_policy(
        UserName=user_name, PolicyName="sim2real-behav-sts", PolicyDocument=json.dumps(policy)
    )
    ctx.on_cleanup(
        lambda: _gone_ok(
            lambda: iam.delete_user_policy(UserName=user_name, PolicyName="sim2real-behav-sts")
        )
    )
    key = iam.create_access_key(UserName=user_name)["AccessKey"]
    key_id = key["AccessKeyId"]
    ctx.on_cleanup(
        lambda: _gone_ok(lambda: iam.delete_access_key(UserName=user_name, AccessKeyId=key_id))
    )
    return {"aws_access_key_id": key_id, "aws_secret_access_key": key["SecretAccessKey"]}


@tags("axis:rejection", "cap:c4", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetFederationToken at the 900 s floor reports Expiration = issuance (the response's Date) +
    900 s within 120 s on both bounds; its credentials perform only what the session policy allows,
    and a duration below the floor is refused with ValidationError.

    Reference: https://docs.aws.amazon.com/STS/latest/APIReference/API_GetFederationToken.html
    """
    # The user's own policy grants CreateBucket, so only the session policy withholds it.
    user_creds = _iam_user_creds(
        ctx,
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["sts:GetFederationToken", "s3:ListAllMyBuckets", "s3:CreateBucket"],
                    "Resource": "*",
                }
            ],
        },
    )
    sts = ctx.client("sts", creds=user_creds)
    bucket_name = ctx.unique_name("sim2real-behav-fed-")
    ctx.on_cleanup(lambda: _delete_bucket_if_exists(ctx.client("s3"), bucket_name))

    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3:ListAllMyBuckets", "Resource": "*"}],
    }
    fed_name = ctx.unique_name("sim2real-fed-")[:32]

    # A new access key and its user policy propagate over seconds: poll the call itself.
    deadline = time.monotonic() + 120.0
    while True:
        try:
            resp = sts.get_federation_token(
                Name=fed_name, Policy=json.dumps(policy_doc), DurationSeconds=_MIN_DURATION_S
            )
            break
        except ClientError as exc:
            if time.monotonic() >= deadline:
                raise AssertionError(
                    "the new IAM user's GetFederationToken never succeeded: "
                    f"{exc.response.get('Error', {}).get('Code')!r}"
                ) from exc
        time.sleep(2.0)

    issued_at = _server_time(resp)
    creds = resp["Credentials"]
    lifetime_s = (creds["Expiration"] - issued_at).total_seconds()
    assert abs(lifetime_s - _MIN_DURATION_S) <= _TOLERANCE_S, (
        f"DurationSeconds={_MIN_DURATION_S} must yield an Expiration {_MIN_DURATION_S}s after "
        f"issuance (within {_TOLERANCE_S}s); got {lifetime_s:.0f}s (issued {issued_at.isoformat()}, "
        f"expires {creds['Expiration'].isoformat()})"
    )
    fed_user_arn = resp["FederatedUser"]["Arn"]
    assert fed_user_arn.endswith(f"federated-user/{fed_name}"), (
        f"FederatedUser.Arn must end in federated-user/{fed_name}; got {fed_user_arn!r}"
    )

    fed_s3 = _client_from_creds(ctx, "s3", creds)

    # Allowed action: the session policy grants s3:ListAllMyBuckets, so an AccessDenied here
    # fails the check.
    fed_s3.list_buckets()

    # Disallowed action (not in the scoping policy) is denied.
    create_kwargs = {"Bucket": bucket_name}
    if ctx.region != "us-east-1":
        # us-east-1 is CreateBucket's default region: S3 rejects it as an explicit
        # LocationConstraint.
        create_kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    code, message = _client_error(lambda: fed_s3.create_bucket(**create_kwargs))
    assert code == "AccessDenied", (
        f"s3:CreateBucket is absent from the session policy, so it must be refused with exactly "
        f"AccessDenied; got {code!r}"
    )
    assert message == (
        f"User: {fed_user_arn} is not authorized to perform: s3:CreateBucket on resource: "
        f'"arn:aws:s3:::{bucket_name}" because no session policy allows the s3:CreateBucket action'
    ), message

    # Effect absent: the bucket the denied call tried to create does not exist.
    admin_names = [b["Name"] for b in ctx.client("s3").list_buckets()["Buckets"]]
    assert bucket_name not in admin_names, (
        f"the denied CreateBucket must have had no effect, but {bucket_name!r} is in the "
        f"account's bucket list"
    )

    # botocore validates min=900 locally; client-side validation is off so 899 reaches STS.
    sts_unvalidated = ctx.client("sts", config=Config(parameter_validation=False), creds=user_creds)
    floor = _client_error(
        lambda: sts_unvalidated.get_federation_token(
            Name=ctx.unique_name("sim2real-fed-short-")[:32], Policy=json.dumps(policy_doc),
            DurationSeconds=_MIN_DURATION_S - 1,
        )
    )
    expected = (
        "ValidationError",
        "1 validation error detected: Value '899' at 'durationSeconds' failed to satisfy "
        "constraint: Member must have value greater than or equal to 900",
    )
    assert floor == expected, f"DurationSeconds=899: expected {expected!r}, got {floor!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
