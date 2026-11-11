"""type-configuration-set-and-batch-describe."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "type-configuration-set-and-batch-describe"
GROUP = "error-semantics"
SERVICES = ["cloudformation"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SetTypeConfiguration persists configuration for an activated extension, and
    BatchDescribeTypeConfigurations returns it while reporting a per-item error for an
    unresolvable identifier in the same call without failing the resolvable ones."""
    cfn = ctx.client("cloudformation")
    iam = ctx.client("iam")
    s3 = ctx.client("s3")

    bucket = _create_bucket(ctx, s3)
    key = "rules.guard"
    s3.put_object(Bucket=bucket, Key=key, Body=b"# sim2real placeholder guard rule\n")

    role_arn = _create_hook_role(ctx, iam, bucket)
    alias = f"Sim2Real::TypeCfg{uuid.uuid4().hex[:16]}::Alias"
    type_arn = _activate_guard_hook(ctx, cfn, alias, role_arn)

    config_payload = {
        "CloudFormationConfiguration": {
            "HookConfiguration": {
                "HookInvocationStatus": "DISABLED",
                "TargetOperations": ["STACK"],
                "FailureMode": "WARN",
                "Properties": {"ruleLocation": {"uri": f"s3://{bucket}/{key}"}},
            }
        }
    }
    set_resp = _set_type_configuration_with_retry(cfn, type_arn, config_payload, alias="default")

    bogus_type_arn = type_arn.rsplit("/", 1)[0] + "/does-not-exist-00000000"
    batch = cfn.batch_describe_type_configurations(
        TypeConfigurationIdentifiers=[
            {"TypeArn": type_arn, "TypeConfigurationAlias": "default"},
            # A bogus TypeArn in the same batch must surface as an error, not crash
            # the whole call -- this is the partial-failure contract of the batch op.
            {"TypeArn": bogus_type_arn, "TypeConfigurationAlias": "default"},
        ]
    )
    good = [c for c in batch["TypeConfigurations"] if c["TypeArn"] == type_arn]
    assert len(good) == 1, f"expected our configuration in the batch result, got {batch}"
    assert json.loads(good[0]["Configuration"]) == config_payload
    assert good[0]["Alias"] == "default"
    assert good[0]["Arn"] == set_resp["ConfigurationArn"], (
        "the independent batch-describe read must resolve to the exact ConfigurationArn "
        f"SetTypeConfiguration minted: {good[0]['Arn']!r} != {set_resp['ConfigurationArn']!r}"
    )

    errors = [
        e
        for e in batch.get("Errors", [])
        if e.get("TypeConfigurationIdentifier", {}).get("TypeArn") == bogus_type_arn
    ]
    unprocessed = [u for u in batch.get("UnprocessedTypeConfigurations", []) if u.get("TypeArn") == bogus_type_arn]
    assert len(errors) + len(unprocessed) == 1, (
        f"expected exactly one failure entry attributed to the bogus TypeArn {bogus_type_arn}, "
        f"got Errors={batch.get('Errors')} UnprocessedTypeConfigurations={batch.get('UnprocessedTypeConfigurations')}"
    )
    if errors:
        assert errors[0]["ErrorCode"] == "404", f"expected a 404 not-found error, got {errors[0]}"


def _create_bucket(ctx, s3) -> str:
    bucket = ctx.unique_name("sim2real-cfnhook-").replace("_", "-").lower()
    kwargs = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    return bucket


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    try:
        resp = s3.list_objects_v2(Bucket=bucket)
        objs = [{"Key": o["Key"]} for o in resp.get("Contents", [])]
        if objs:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objs}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _create_hook_role(ctx, iam, bucket: str) -> str:
    role_name = ctx.unique_name("sim2real-cfnhook-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "hooks.cloudformation.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    policy_name = "sim2real-guard-hook-s3-read"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["s3:ListBucket", "s3:GetObject", "s3:GetObjectVersion"],
                        "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _activate_guard_hook(ctx, cfn, alias: str, role_arn: str) -> str:
    # ActivateType right after a fresh IAM role's trust policy is written can 403 for a few
    # seconds until the policy propagates, hence the bounded retry.
    deadline = time.monotonic() + 60.0
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            resp = cfn.activate_type(
                Type="HOOK",
                TypeName="AWS::Hooks::GuardHook",
                PublisherId="aws-hooks",
                TypeNameAlias=alias,
                ExecutionRoleArn=role_arn,
            )
            type_arn = resp["Arn"]
            ctx.on_cleanup(lambda: cfn.deactivate_type(Arn=type_arn))
            return type_arn
        except ClientError as exc:
            last_exc = exc
            time.sleep(3)
    raise AssertionError(f"ActivateType for AWS::Hooks::GuardHook never succeeded: {last_exc}")


def _set_type_configuration_with_retry(cfn, type_arn: str, config: dict, *, alias: str) -> dict:
    # A newly-activated type can be momentarily invisible to SetTypeConfiguration,
    # for the same IAM/registry-propagation reason as above.
    deadline = time.monotonic() + 60.0
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return cfn.set_type_configuration(
                TypeArn=type_arn, Configuration=json.dumps(config), ConfigurationAlias=alias
            )
        except ClientError as exc:
            last_exc = exc
            time.sleep(3)
    raise AssertionError(f"SetTypeConfiguration never succeeded: {last_exc}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
