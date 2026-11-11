"""select-object-content-permission-denied."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "select-object-content-permission-denied"
GROUP = "overly-permissive"
SERVICES = ["s3"]


@tags("axis:rejection", "cap:c6", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A caller without s3:GetObject is denied SelectObjectContent with AccessDenied and its exact message
    and gets no records; once granted s3:GetObject, the same call fails only with the exact
    MethodNotAllowed of the withdrawn API, still without records."""
    iam = ctx.client("iam")
    s3 = ctx.client("s3")
    bucket = _create_bucket(ctx)
    key = "secret.jsonl"
    body = b'{"a": 1}\n{"a": 2}\n{"a": 3}\n'
    s3.put_object(Bucket=bucket, Key=key, Body=body)
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=key))

    # Positive control, decoupled from SelectObjectContent entirely: the object and the owner's
    # credentials are otherwise healthy for S3.
    fetched = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
    assert fetched == body, (
        f"positive control: a plain GetObject on the same object must return the bytes written; "
        f"got {fetched!r}"
    )

    user_name = ctx.unique_name("sim2real-s3select-user-")
    user_arn = iam.create_user(UserName=user_name)["User"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))

    policy_name = "no-get-object"
    policy_doc = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                # Grants an unrelated permission but NOT s3:GetObject on the
                # target bucket/object -- IAM's default-deny means
                # SelectObjectContent (which requires s3:GetObject) is denied.
                {"Effect": "Allow", "Action": "s3:ListAllMyBuckets", "Resource": "*"},
            ],
        }
    )
    iam.put_user_policy(UserName=user_name, PolicyName=policy_name, PolicyDocument=policy_doc)
    ctx.on_cleanup(lambda: iam.delete_user_policy(UserName=user_name, PolicyName=policy_name))

    access_key = iam.create_access_key(UserName=user_name)["AccessKey"]
    access_key_id = access_key["AccessKeyId"]
    secret_access_key = access_key["SecretAccessKey"]
    ctx.on_cleanup(lambda: iam.delete_access_key(UserName=user_name, AccessKeyId=access_key_id))

    _wait_for_iam_credentials(ctx, access_key_id, secret_access_key)
    restricted_s3 = _client_with_creds(ctx, "s3", access_key_id, secret_access_key)

    def _select(client):
        """(code, message, got_records) for one refused SelectObjectContent attempt.

        Raises AssertionError when the call succeeds, saying whether any Records came back.
        """
        try:
            resp = client.select_object_content(
                Bucket=bucket,
                Key=key,
                Expression="SELECT * FROM S3Object s",
                ExpressionType="SQL",
                InputSerialization={"JSON": {"Type": "LINES"}},
                OutputSerialization={"JSON": {}},
            )
        except ClientError as exc:
            error = exc.response["Error"]
            return error["Code"], error.get("Message", ""), False
        got = any("Records" in event for event in resp["Payload"])
        raise AssertionError(
            f"SelectObjectContent was expected to be refused and it succeeded (records: {got!r})"
        )

    code, message, got_records = _select(restricted_s3)
    assert code == "AccessDenied", (
        f"a caller whose identity policy grants no s3:GetObject must be refused "
        f"SelectObjectContent with AccessDenied; got code={code!r} got_records={got_records!r}"
    )
    want_message = (
        f'User: {user_arn} is not authorized to perform: s3:GetObject on resource: '
        f'"arn:aws:s3:::{bucket}/{key}" because no identity-based policy allows the s3:GetObject '
        f'action'
    )
    assert message == want_message, (
        f"the AccessDenied message is {message!r}, want {want_message!r}"
    )
    assert not got_records, "the denied caller must never receive any Records data"
    # The denial happens on the initial call itself (a plain 403 ClientError, not a
    # partially-consumed event stream), so no Records data was ever produced for the
    # unauthorized caller -- `_select` returns got_records=False on every ClientError path.

    # Restore: grant the SAME restricted user s3:GetObject on this object and replay the
    # IDENTICAL call. S3 Select is closed to new accounts, so no caller gets a successful Select
    # response; the permitted caller's verdict must change from AccessDenied to that fixed refusal,
    # proving the AccessDenied came from IAM.
    object_arn = f"arn:aws:s3:::{bucket}/{key}"
    iam.put_user_policy(
        UserName=user_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": "s3:ListAllMyBuckets", "Resource": "*"},
                    {"Effect": "Allow", "Action": "s3:GetObject", "Resource": object_arn},
                ],
            }
        ),
    )

    deadline = time.monotonic() + 60.0
    restored_code, restored_message, restored_records = _select(restricted_s3)
    while restored_code == "AccessDenied":
        if time.monotonic() >= deadline:
            break
        time.sleep(2.0)
        restored_code, restored_message, restored_records = _select(restricted_s3)
    assert restored_code != "AccessDenied", (
        f"granting s3:GetObject to the SAME restricted user must change the identical "
        f"SelectObjectContent call's verdict away from AccessDenied within 60s; still "
        f"{restored_code!r}"
    )
    assert restored_code == "MethodNotAllowed", (
        f"once permitted, this account's fixed answer for SelectObjectContent must be exactly "
        f"MethodNotAllowed (AWS discontinued S3 Select for accounts created after 2024-07-25), "
        f"not a different code; got {restored_code!r} message={restored_message!r}"
    )
    assert restored_message == "The specified method is not allowed against this resource.", (
        f"MethodNotAllowed's message is {restored_message!r}, want "
        "'The specified method is not allowed against this resource.'"
    )
    assert not restored_records, "the now-permitted caller must still never receive Records data"


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-s3select-")
    kwargs = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
    return bucket


def _client_with_creds(ctx, service: str, access_key_id: str, secret_access_key: str):
    return ctx.client(service, creds={"aws_access_key_id": access_key_id,
                                      "aws_secret_access_key": secret_access_key})


def _wait_for_iam_credentials(
    ctx, access_key_id: str, secret_access_key: str, timeout_s: float = 60.0, interval_s: float = 2.0
) -> None:
    """Poll with the new access key until IAM eventual-consistency clears."""
    sts = _client_with_creds(ctx, "sts", access_key_id, secret_access_key)
    deadline = time.monotonic() + timeout_s
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            sts.get_caller_identity()
            return
        except Exception as exc:  # noqa: BLE001 - eventual consistency retry
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(f"IAM credentials never became usable within {timeout_s}s: {last_exc}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
