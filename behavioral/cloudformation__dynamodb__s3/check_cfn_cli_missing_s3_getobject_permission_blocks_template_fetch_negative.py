"""cfn-cli-missing-s3-getobject-permission-blocks-template-fetch-negative."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "cfn-cli-missing-s3-getobject-permission-blocks-template-fetch-negative"
GROUP = "overly-permissive"
SERVICES = ["cloudformation", "dynamodb", "s3"]

_TEMPLATE = json.dumps(
    {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {"Handle": {"Type": "AWS::CloudFormation::WaitConditionHandle"}},
    }
)


def _managed_tags_kv() -> list[dict[str, str]]:
    return [{"Key": "sim2real:managed", "Value": "true"}]


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CloudFormation fetches a TemplateURL with the caller's own S3 permissions: an IAM user allowed
    CreateStack but no S3 access gets ValidationError with the exact message and no stack exists,
    while the same URL reaches CREATE_COMPLETE for a fully permissioned caller (positive control)."""
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    cfn = ctx.client("cloudformation")

    bucket = ctx.unique_name("sim2real-cfniamneg-")
    _create_bucket(ctx, s3, bucket)
    key = "templates/handle.json"
    s3.put_object(Bucket=bucket, Key=key, Body=_TEMPLATE.encode())
    template_url = f"https://{bucket}.s3.{ctx.region}.amazonaws.com/{key}"

    # --- Positive control: fully-permissioned caller succeeds. ---
    stack_ok = ctx.unique_name("sim2real-cfniamneg-ok-")

    def _cleanup_ok():
        cfn.delete_stack(StackName=stack_ok)
        _wait_stack_status(ctx, cfn, stack_ok, {"DELETE_COMPLETE"}, timeout_s=180.0)

    ctx.on_cleanup(_cleanup_ok)
    cfn.create_stack(StackName=stack_ok, TemplateURL=template_url, Tags=_managed_tags_kv())
    ok_status = _wait_stack_status(ctx, cfn, stack_ok, {"CREATE_COMPLETE"}, timeout_s=180.0)
    assert ok_status == "CREATE_COMPLETE"

    # --- Build a restricted IAM identity: CloudFormation actions allowed, no S3 at all. ---
    username = ctx.unique_name("sim2real-cfniamneg-user-")
    iam.create_user(UserName=username, Tags=_managed_tags_kv())
    ctx.on_cleanup(lambda: iam.delete_user(UserName=username))

    policy_name = "cloudformation-only"
    iam.put_user_policy(
        UserName=username,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "cloudformation:CreateStack",
                            "cloudformation:DescribeStacks",
                            "cloudformation:DeleteStack",
                        ],
                        "Resource": "*",
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_user_policy(UserName=username, PolicyName=policy_name))

    key_pair = iam.create_access_key(UserName=username)["AccessKey"]
    access_key_id = key_pair["AccessKeyId"]
    secret_access_key = key_pair["SecretAccessKey"]
    ctx.on_cleanup(lambda: iam.delete_access_key(UserName=username, AccessKeyId=access_key_id))

    restricted_cfn = ctx.client(
        "cloudformation",
        creds={"aws_access_key_id": access_key_id, "aws_secret_access_key": secret_access_key},
    )

    # New IAM credentials can take a few seconds to propagate; poll for usability first.
    _wait_credentials_usable(restricted_cfn, timeout_s=30.0)

    stack_denied = ctx.unique_name("sim2real-cfniamneg-denied-")
    code, message = _client_error(
        lambda: restricted_cfn.create_stack(
            StackName=stack_denied, TemplateURL=template_url, Tags=_managed_tags_kv()
        )
    )
    assert code == "ValidationError", f"expected ValidationError from missing S3 permission, got {code!r}"
    expected = (
        "S3 error: Access Denied\n"
        "For more information check http://docs.aws.amazon.com/AmazonS3/latest/API/ErrorResponses.html"
    )
    assert message == expected, f"expected {expected!r}, got {message!r}"

    # No stack was left behind by the failed attempt (checked with the fully-permissioned caller).
    describe_code, describe_message = _client_error(lambda: cfn.describe_stacks(StackName=stack_denied))
    assert describe_code == "ValidationError", (
        f"expected stack {stack_denied} to be absent, got {describe_code!r}"
    )
    expected = f"Stack with id {stack_denied} does not exist"
    assert describe_message == expected, f"expected {expected!r}, got {describe_message!r}"


def _create_bucket(ctx, s3, name: str) -> None:
    kwargs = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, name))
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": _managed_tags_kv()})


def _empty_and_delete_bucket(s3, name: str) -> None:
    try:
        resp = s3.list_objects_v2(Bucket=name)
        keys = [{"Key": o["Key"]} for o in resp.get("Contents", [])]
        if keys:
            failed = s3.delete_objects(Bucket=name, Delete={"Objects": keys}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    try:
        s3.delete_bucket(Bucket=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _client_error(fn) -> tuple[str, str]:
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises, so an
    over-permissive target is reported as accepting the call, not as a code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code", ""), err.get("Message", "")
    raise AssertionError(f"expected a ClientError but the call succeeded: {result!r}")


def _wait_credentials_usable(client, timeout_s=30.0, interval_s=2.0):
    """New IAM access keys can take a few seconds to become usable; poll a harmless,
    already-granted call until it stops failing on auth (InvalidClientTokenId)."""
    deadline = time.monotonic() + timeout_s
    last_code = None
    while time.monotonic() < deadline:
        try:
            client.describe_stacks(StackName="sim2real-nonexistent-probe-stack")
            return
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            if code != "InvalidClientTokenId":
                return
        last_code = code
        time.sleep(interval_s)
    raise AssertionError(f"restricted IAM credentials never became usable (last={last_code})")


def _wait_stack_status(ctx, cfn, stack_name, target_statuses, timeout_s=300.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            resp = cfn.describe_stacks(StackName=stack_name)
        except ClientError:
            if "DELETE_COMPLETE" in target_statuses:
                return "DELETE_COMPLETE"
            raise
        last = resp["Stacks"][0]["StackStatus"]
        if last in target_statuses:
            return last
        if last.endswith("FAILED"):
            raise AssertionError(f"stack {stack_name} entered unexpected status {last}")
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name} did not reach {target_statuses} within {timeout_s}s (last={last})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
