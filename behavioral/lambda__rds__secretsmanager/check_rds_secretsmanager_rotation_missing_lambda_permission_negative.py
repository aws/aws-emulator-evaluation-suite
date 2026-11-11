"""rds-secretsmanager-rotation-missing-lambda-permission-negative."""
from __future__ import annotations

import io
import json
import time
import uuid
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "rds-secretsmanager-rotation-missing-lambda-permission-negative"
GROUP = "permission-boundary"
SERVICES = ["lambda", "rds", "secretsmanager"]


@tags("axis:rejection", "cap:c3", "cap:c4", "cap:c7", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """Rotation never progresses (RDS credentials untouched) when the Lambda lacks a resource
    policy granting secretsmanager.amazonaws.com invoke permission; granting it lets the same
    secret/function pair rotate successfully."""
    ctx.client("rds")
    secretsmanager = ctx.client("secretsmanager")
    lam = ctx.client("lambda")
    logs = ctx.client("logs")

    vpc_id = _default_vpc_id(ctx)
    if vpc_id is None:
        raise AssertionError("account has no shared network VPC; cannot provision the test RDS instance")
    subnet_group = _create_db_subnet_group(ctx, vpc_id)

    db_id = ctx.unique_name("sim2real-rot-db-")
    original_password = _gen_password()
    inst = _create_mysql_instance(ctx, db_id, original_password, subnet_group=subnet_group)

    secret_name = ctx.unique_name("sim2real-rot-secret-")
    secret_arn = _create_secret_for_db(ctx, secretsmanager, secret_name, inst, "rotator", original_password)

    role_arn = _create_lambda_role(ctx)
    fn_name = ctx.unique_name("sim2real-rot-fn-")
    fn_arn = _create_rotation_lambda(ctx, role_arn, fn_name)
    # Deliberately NOT granting secretsmanager.amazonaws.com invoke permission on the function.

    original = json.loads(secretsmanager.get_secret_value(SecretId=secret_arn)["SecretString"])

    # RotateSecret validates that Secrets Manager can invoke the Lambda BEFORE starting the
    # rotation cycle: with no resource-policy grant on the function, the call itself is rejected
    # synchronously — the rotation never starts and RDS credentials are never touched.
    denied_code, denied_message = _error_code(
        lambda: secretsmanager.rotate_secret(
            SecretId=secret_arn,
            RotationLambdaARN=fn_arn,
            RotationRules={"AutomaticallyAfterDays": 1},
            RotateImmediately=True,
        )
    )
    assert denied_code == "AccessDeniedException", (
        f"expected AccessDeniedException for the unauthorized invoke, got {denied_code!r}: {denied_message!r}"
    )
    assert denied_message == _CANNOT_INVOKE, f"unexpected RotateSecret refusal message: {denied_message!r}"

    # Effect absent: no rotation ever started (no AWSPENDING stage, no log group, unchanged password).
    stages = secretsmanager.describe_secret(SecretId=secret_arn)["VersionIdsToStages"]
    assert not any("AWSPENDING" in v for v in stages.values()), (
        "rotation progressed to AWSPENDING despite the rejected RotateSecret call"
    )

    unchanged = json.loads(
        secretsmanager.get_secret_value(SecretId=secret_arn, VersionStage="AWSCURRENT")["SecretString"]
    )
    assert unchanged["password"] == original["password"], "RDS credentials changed despite blocked rotation"

    log_group = f"/aws/lambda/{fn_name}"
    code, message = _error_code(lambda: logs.filter_log_events(logGroupName=log_group, filterPattern="ROTATION_STEP"))
    assert code == "ResourceNotFoundException", (
        f"expected no log group (function never invoked), got error code {code!r}: {message!r}"
    )
    assert message == "The specified log group does not exist.", f"unexpected FilterLogEvents message: {message!r}"

    # Positive control: grant the permission and rotate the SAME secret/function - now it must work.
    original_version = _current_version_id(secretsmanager, secret_arn)
    _add_invoke_permission(ctx, lam, fn_name)
    secretsmanager.rotate_secret(
        SecretId=secret_arn,
        RotationLambdaARN=fn_arn,
        RotationRules={"AutomaticallyAfterDays": 1},
        RotateImmediately=True,
    )
    # AWSCURRENT moving to a new version id is finishSecret's actual completion signal. Real AWS
    # does not necessarily strip the AWSPENDING label from that version when AWSCURRENT moves onto
    # it (the two labels can coexist on the same version well after rotation has completed), so
    # waiting for AWSPENDING to vanish would never end.
    new_version = _poll_until(
        lambda: _current_version_id(secretsmanager, secret_arn),
        lambda version: version != original_version,
        timeout_s=200.0,
        interval_s=5.0,
    )
    stages_after = secretsmanager.describe_secret(SecretId=secret_arn)["VersionIdsToStages"]
    assert "AWSPREVIOUS" in stages_after.get(original_version, []), (
        "the pre-rotation version was not preserved under AWSPREVIOUS"
    )
    rotated = json.loads(
        secretsmanager.get_secret_value(SecretId=secret_arn, VersionId=new_version)["SecretString"]
    )
    assert rotated["password"] != original["password"], "control rotation did not change the password"


# ===== helpers =====


_CANNOT_INVOKE = (
    "Secrets Manager cannot invoke the specified Lambda function. Ensure that the function "
    "policy grants access to the principal secretsmanager.amazonaws.com."
)

LAMBDA_SRC = r'''
import json
import boto3

def lambda_handler(event, context):
    arn = event["SecretId"]
    token = event["ClientRequestToken"]
    step = event["Step"]
    print(f"ROTATION_STEP step={step} secret={arn} token={token}")

    svc = boto3.client("secretsmanager")
    metadata = svc.describe_secret(SecretId=arn)
    if not metadata.get("RotationEnabled", False):
        raise ValueError(f"Secret {arn} is not enabled for rotation")

    # The "already AWSCURRENT" idempotency check belongs ONLY inside finishSecret (a retried
    # finishSecret invocation after an earlier one already promoted this token) -- guarding
    # every step with it is wrong: it makes createSecret/setSecret/testSecret no-op whenever
    # Secrets Manager's token happens to coincide with the pre-rotation AWSCURRENT version,
    # which permanently strands the AWSPENDING label with nothing left to clear it.
    if step == "createSecret":
        current = json.loads(svc.get_secret_value(SecretId=arn, VersionStage="AWSCURRENT")["SecretString"])
        try:
            svc.get_secret_value(SecretId=arn, VersionId=token, VersionStage="AWSPENDING")
        except svc.exceptions.ResourceNotFoundException:
            new_password = svc.get_random_password(PasswordLength=24, ExcludePunctuation=True)["RandomPassword"]
            current["password"] = new_password
            svc.put_secret_value(
                SecretId=arn, ClientRequestToken=token,
                SecretString=json.dumps(current), VersionStages=["AWSPENDING"],
            )
    elif step == "setSecret":
        # Resolve the RDS binding via the real API (the cross-service edge under test);
        # deliberately does NOT call ModifyDBInstance/wait-for-available, since a fresh RDS
        # instance's provisioning time (5-15 min) would dwarf the check's own budget.
        pending = json.loads(svc.get_secret_value(SecretId=arn, VersionId=token, VersionStage="AWSPENDING")["SecretString"])
        rds = boto3.client("rds")
        rds.describe_db_instances(DBInstanceIdentifier=pending["dbInstanceIdentifier"])
    elif step == "testSecret":
        pending = json.loads(svc.get_secret_value(SecretId=arn, VersionId=token, VersionStage="AWSPENDING")["SecretString"])
        rds = boto3.client("rds")
        resp = rds.describe_db_instances(DBInstanceIdentifier=pending["dbInstanceIdentifier"])
        if not resp["DBInstances"]:
            raise ValueError(f"db instance {pending['dbInstanceIdentifier']} not found")
    elif step == "finishSecret":
        current_version = None
        for version, stages in metadata["VersionIdsToStages"].items():
            if "AWSCURRENT" in stages:
                if version == token:
                    return
                current_version = version
                break
        svc.update_secret_version_stage(
            SecretId=arn, VersionStage="AWSCURRENT",
            MoveToVersionId=token, RemoveFromVersionId=current_version,
        )
    else:
        raise ValueError(f"Invalid step {step} for {arn}")
'''


def _error_code(fn):
    """Call fn() and return its (code, message); a call that succeeds raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _gen_password() -> str:
    return f"Rot8{uuid.uuid4().hex[:20]}Aa"


def _poll_until(probe, predicate, *, timeout_s: float = 60.0, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _current_version_id(secretsmanager, secret_arn: str) -> str:
    stages = secretsmanager.describe_secret(SecretId=secret_arn)["VersionIdsToStages"]
    for version, labels in stages.items():
        if "AWSCURRENT" in labels:
            return version
    raise AssertionError(f"secret {secret_arn} has no AWSCURRENT version")


def _default_vpc_id(ctx) -> str | None:
    ec2 = ctx.client("ec2")
    resp = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])
    vpcs = resp.get("Vpcs", [])
    return vpcs[0]["VpcId"] if vpcs else None


def _create_db_subnet_group(ctx, vpc_id: str) -> str | None:
    ec2 = ctx.client("ec2")
    rds = ctx.client("rds")
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az: dict[str, str] = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    subnet_ids = list(by_az.values())[:3]
    if len(subnet_ids) < 2:
        return None
    name = ctx.unique_name("sim2real-rot-subnets-")
    rds.create_db_subnet_group(
        DBSubnetGroupName=name,
        DBSubnetGroupDescription="sim2real rotation test",
        SubnetIds=subnet_ids,
    )
    ctx.on_cleanup(lambda: _best_effort(lambda: rds.delete_db_subnet_group(DBSubnetGroupName=name)))
    return name


# Teardown deletes return on the resource's not-found code, retry while a dependency is still
# being released (an instance still creating, a subnet group still in use), and raise the rest.
_GONE_CODES = ("DBSubnetGroupNotFoundFault", "DBInstanceNotFound", "NoSuchEntity", "ResourceNotFoundException")
_BUSY_CODES = ("InvalidDBSubnetGroupStateFault", "InvalidDBInstanceState", "DependencyViolation")


def _best_effort(fn, timeout_s: float = 840.0) -> None:
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code in _GONE_CODES:
                return
            if code not in _BUSY_CODES or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _create_mysql_instance(ctx, db_id: str, master_password: str, subnet_group: str | None = None) -> dict[str, Any]:
    """Kick off RDS provisioning and return as soon as the instance record EXISTS — deliberately
    does not wait for "available" (5-15 min on real AWS, far beyond a single check's budget)."""
    rds = ctx.client("rds")
    kwargs: dict[str, Any] = dict(
        DBInstanceIdentifier=db_id,
        DBInstanceClass="db.t3.micro",
        Engine="mysql",
        MasterUsername="rotator",
        MasterUserPassword=master_password,
        AllocatedStorage=20,
        BackupRetentionPeriod=0,
        PubliclyAccessible=False,
    )
    if subnet_group:
        kwargs["DBSubnetGroupName"] = subnet_group
    resp = rds.create_db_instance(**kwargs)
    ctx.on_cleanup(lambda: _best_effort(lambda: rds.delete_db_instance(DBInstanceIdentifier=db_id, SkipFinalSnapshot=True)))
    return resp["DBInstance"]


def _create_secret_for_db(ctx, secretsmanager, secret_name: str, inst: dict[str, Any], username: str, password: str) -> str:
    secret_dict = {
        "engine": "mysql",
        "username": username,
        "password": password,
        "dbInstanceIdentifier": inst["DBInstanceIdentifier"],
    }
    resp = secretsmanager.create_secret(Name=secret_name, SecretString=json.dumps(secret_dict))
    ctx.on_cleanup(lambda: secretsmanager.delete_secret(SecretId=resp["ARN"], ForceDeleteWithoutRecovery=True))
    return resp["ARN"]


def _create_lambda_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-rot-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: _best_effort(lambda: iam.delete_role(RoleName=role_name)))
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                "Resource": "*",
            },
            {
                "Effect": "Allow",
                "Action": [
                    "secretsmanager:GetSecretValue",
                    "secretsmanager:PutSecretValue",
                    "secretsmanager:UpdateSecretVersionStage",
                    "secretsmanager:DescribeSecret",
                    "secretsmanager:GetRandomPassword",
                ],
                "Resource": "*",
            },
            {
                "Effect": "Allow",
                "Action": ["rds:ModifyDBInstance", "rds:DescribeDBInstances"],
                "Resource": "*",
            },
        ],
    }
    policy_name = ctx.unique_name("sim2real-rot-policy-")
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: _best_effort(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)))
    return role_arn


def _build_zip(src: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", src)
    return buf.getvalue()


def _create_rotation_lambda(ctx, role_arn: str, name: str) -> str:
    lam = ctx.client("lambda")
    zip_bytes = _build_zip(LAMBDA_SRC)
    fn = None
    for attempt in range(8):
        try:
            ctx.on_cleanup(lambda _n=name: _delete_lambda_log_group(ctx, _n))
            fn = lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="lambda_function.lambda_handler",
                Code={"ZipFile": zip_bytes},
                Timeout=300,
                MemorySize=128,
            )
            break
        except ClientError as err:
            if err.response["Error"]["Code"] == "InvalidParameterValueException" and attempt < 7:
                time.sleep(5)
                continue
            raise
    ctx.on_cleanup(lambda: _best_effort(lambda: lam.delete_function(FunctionName=name)))
    _poll_until(
        lambda: lam.get_function(FunctionName=name)["Configuration"]["State"],
        lambda s: s == "Active",
        timeout_s=120.0,
        interval_s=3.0,
    )
    return fn["FunctionArn"]


def _add_invoke_permission(ctx, lam, function_name: str, statement_id: str = "AllowSecretsManagerInvoke") -> None:
    lam.add_permission(
        FunctionName=function_name,
        StatementId=statement_id,
        Action="lambda:InvokeFunction",
        Principal="secretsmanager.amazonaws.com",
    )
    ctx.on_cleanup(lambda: _best_effort(lambda: lam.remove_permission(FunctionName=function_name, StatementId=statement_id)))


def _delete_lambda_log_group(ctx, function_name: str) -> None:
    """Delete the log group Lambda creates on a function's first log line; one never created is fine."""
    try:
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{function_name}")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
