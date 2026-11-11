"""concurrent-batch-describe-type-configurations-consistent-snapshot."""
from __future__ import annotations

import json
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "concurrent-batch-describe-type-configurations-consistent-snapshot"
GROUP = "concurrency"
SERVICES = ["cloudformation"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """BatchDescribeTypeConfigurations reads racing a SetTypeConfiguration write each see exactly the
    old or the new Configuration, never a torn mix, and the type ends on the new value."""
    cfn = ctx.client("cloudformation")
    iam = ctx.client("iam")
    s3 = ctx.client("s3")

    bucket = ctx.unique_name("sim2real-cfn-hook-").lower().replace("_", "-")
    _create_bucket(ctx, s3, bucket)
    s3.put_object(Bucket=bucket, Key="rules-v1.guard", Body=b"# sim2real placeholder guard rule v1\n")
    s3.put_object(Bucket=bucket, Key="rules-v2.guard", Body=b"# sim2real placeholder guard rule v2\n")

    role_name = ctx.unique_name("sim2real-cfn-hook-role-")
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
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    inline_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:ListBucket", "s3:GetObject", "s3:GetObjectVersion"],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            }
        ],
    }
    policy_name = "sim2real-guard-hook-s3-read"
    iam.put_role_policy(
        RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(inline_policy)
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))

    alias = f"Sim2Real::GuardHook{uuid.uuid4().hex[:16]}::Alias"
    type_arn = _activate_guard_hook(cfn, alias, role_arn)
    ctx.on_cleanup(lambda: cfn.deactivate_type(Arn=type_arn))

    config_v1 = {
        "CloudFormationConfiguration": {
            "HookConfiguration": {
                "HookInvocationStatus": "DISABLED",
                "TargetOperations": ["STACK"],
                "FailureMode": "WARN",
                "Properties": {"ruleLocation": {"uri": f"s3://{bucket}/rules-v1.guard"}},
            }
        }
    }
    config_v2 = {
        "CloudFormationConfiguration": {
            "HookConfiguration": {
                "HookInvocationStatus": "DISABLED",
                "TargetOperations": ["STACK"],
                "FailureMode": "WARN",
                "Properties": {"ruleLocation": {"uri": f"s3://{bucket}/rules-v2.guard"}},
            }
        }
    }

    _set_type_configuration_with_retry(cfn, type_arn, config_v1)

    baseline = cfn.batch_describe_type_configurations(
        TypeConfigurationIdentifiers=[{"TypeArn": type_arn}]
    )
    baseline_config = json.loads(baseline["TypeConfigurations"][0]["Configuration"])
    assert baseline_config == config_v1, (
        f"expected the just-written config_v1 before any concurrency, got {baseline_config}"
    )

    start = threading.Event()
    read_results: list[dict] = []
    read_errors: list[BaseException] = []

    def writer() -> None:
        start.wait()
        cfn.set_type_configuration(TypeArn=type_arn, Configuration=json.dumps(config_v2))

    def reader() -> None:
        start.wait()
        try:
            resp = cfn.batch_describe_type_configurations(
                TypeConfigurationIdentifiers=[{"TypeArn": type_arn}]
            )
            read_results.append(resp)
        except BaseException as exc:  # noqa: BLE001
            read_errors.append(exc)

    with ThreadPoolExecutor(max_workers=6) as pool:
        futures = [pool.submit(writer)] + [pool.submit(reader) for _ in range(5)]
        start.set()
        for fut in futures:
            fut.result(timeout=60)

    assert not read_errors, f"concurrent BatchDescribeTypeConfigurations reads raised: {read_errors}"
    assert len(read_results) == 5, f"expected all 5 concurrent readers to complete, got {len(read_results)}"

    for resp in read_results:
        assert not resp.get("Errors"), f"expected no per-item errors, got {resp.get('Errors')}"
        assert not resp.get("UnprocessedTypeConfigurations"), (
            f"expected no unprocessed identifiers, got {resp.get('UnprocessedTypeConfigurations')}"
        )
        configs = resp["TypeConfigurations"]
        assert len(configs) == 1, f"expected exactly one TypeConfiguration entry, got {configs}"
        parsed = json.loads(configs[0]["Configuration"])
        assert parsed in (config_v1, config_v2), (
            f"torn/unknown Configuration snapshot observed during concurrent write: {parsed}"
        )

    final = cfn.batch_describe_type_configurations(
        TypeConfigurationIdentifiers=[{"TypeArn": type_arn}]
    )
    final_config = json.loads(final["TypeConfigurations"][0]["Configuration"])
    assert final_config == config_v2, (
        f"expected the type settled on config_v2 after the writer joined, got {final_config}"
    )


def _create_bucket(ctx, s3, bucket: str) -> None:
    # us-east-1 rejects a CreateBucketConfiguration with LocationConstraint=us-east-1 --
    # it is the one region S3 will not name explicitly.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real:managed", "Value": "true"}]}
    )

    def _cleanup() -> None:
        for obj in s3.list_objects_v2(Bucket=bucket).get("Contents", []):
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)


def _activate_guard_hook(cfn, alias: str, role_arn: str) -> str:
    deadline = time.monotonic() + 60.0
    last_exc: BaseException | None = None
    while time.monotonic() < deadline:
        try:
            resp = cfn.activate_type(
                Type="HOOK",
                TypeName="AWS::Hooks::GuardHook",
                PublisherId="aws-hooks",
                TypeNameAlias=alias,
                ExecutionRoleArn=role_arn,
            )
            return resp["Arn"]
        except Exception as exc:  # noqa: BLE001 -- IAM trust-policy propagation lag
            last_exc = exc
            time.sleep(3)
    raise AssertionError(f"ActivateType for AWS::Hooks::GuardHook never succeeded: {last_exc}")


def _set_type_configuration_with_retry(cfn, type_arn: str, config: dict) -> None:
    deadline = time.monotonic() + 60.0
    last_exc: BaseException | None = None
    while time.monotonic() < deadline:
        try:
            cfn.set_type_configuration(TypeArn=type_arn, Configuration=json.dumps(config))
            return
        except Exception as exc:  # noqa: BLE001 -- newly-activated type may not be visible yet
            last_exc = exc
            time.sleep(3)
    raise AssertionError(f"SetTypeConfiguration never succeeded: {last_exc}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
