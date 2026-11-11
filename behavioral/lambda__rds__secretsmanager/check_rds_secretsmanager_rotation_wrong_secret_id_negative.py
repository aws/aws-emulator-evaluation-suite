"""rds-secretsmanager-rotation-wrong-secret-id-negative."""

from __future__ import annotations

import io
import json
import time
import uuid
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "rds-secretsmanager-rotation-wrong-secret-id-negative"
GROUP = "permission-boundary"
SERVICES = ["lambda", "rds", "secretsmanager"]


@tags(
    "axis:negative-delivery",
    "cap:c3",
    "cap:c4",
    "concern:data-plane",
    "concern:e2e",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """Rotating an unrelated secret through the RDS-bound rotation function never completes
    (the Lambda's setSecret step needs a dbInstanceIdentifier field that the unrelated secret
    lacks); rotating the correctly-bound secret through the same function does complete."""
    secretsmanager = ctx.client("secretsmanager")
    lam = ctx.client("lambda")

    vpc_id = _default_vpc_id(ctx)
    if vpc_id is None:
        raise AssertionError(
            "account has no default VPC; cannot provision the test RDS instance"
        )
    subnet_group = _create_db_subnet_group(ctx, vpc_id)

    db_id = ctx.unique_name("sim2real-rot-db-")
    original_password = _gen_password()
    inst = _create_mysql_instance(
        ctx, db_id, original_password, subnet_group=subnet_group
    )

    secret_a_name = ctx.unique_name("sim2real-rot-secreta-")
    secret_a_arn = _create_secret_for_db(
        ctx, secretsmanager, secret_a_name, inst, "rotator", original_password
    )

    secret_b_name = ctx.unique_name("sim2real-rot-secretb-")
    secret_b_resp = secretsmanager.create_secret(
        Name=secret_b_name,
        SecretString=json.dumps(
            {"note": "unrelated-credential", "password": "not-used-for-rds"}
        ),
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    secret_b_arn = secret_b_resp["ARN"]
    ctx.on_cleanup(
        lambda: secretsmanager.delete_secret(
            SecretId=secret_b_arn, ForceDeleteWithoutRecovery=True
        )
    )

    role_arn = _create_lambda_role(ctx)
    fn_name = ctx.unique_name("sim2real-rot-fn-")
    fn_arn = _create_rotation_lambda(ctx, role_arn, fn_name)
    _add_invoke_permission(ctx, lam, fn_name)

    stages_before = secretsmanager.describe_secret(SecretId=secret_b_arn)[
        "VersionIdsToStages"
    ]
    original_current_version = [
        v for v, s in stages_before.items() if "AWSCURRENT" in s
    ][0]

    # Attempt to rotate the UNRELATED secret through the RDS-bound rotation function.
    secretsmanager.rotate_secret(
        SecretId=secret_b_arn,
        RotationLambdaARN=fn_arn,
        RotationRules={"AutomaticallyAfterDays": 1},
        RotateImmediately=True,
    )

    # It must never complete (setSecret needs a "dbInstanceIdentifier" field that secret B lacks),
    # so the AWSCURRENT version of secret B must stay pinned to its pre-rotation version the whole time.
    deadline = time.monotonic() + 40.0
    while time.monotonic() < deadline:
        stages = secretsmanager.describe_secret(SecretId=secret_b_arn)[
            "VersionIdsToStages"
        ]
        current_versions = [v for v, s in stages.items() if "AWSCURRENT" in s]
        assert current_versions == [original_current_version], (
            "secret B's AWSCURRENT version moved even though its payload is not RDS-bound"
        )
        time.sleep(2)

    # Effect absent on the real target: secret A (the correctly RDS-bound secret) is untouched.
    secret_a_unchanged = json.loads(
        secretsmanager.get_secret_value(SecretId=secret_a_arn)["SecretString"]
    )
    assert secret_a_unchanged["password"] == original_password

    # Secret B's rotation never reaches a terminal state (setSecret KeyErrors every attempt), so
    # Secrets Manager still considers it "in progress" against the shared rotation function. Cancel
    # it explicitly before reusing that function for secret A — otherwise the still-pending rotation
    # on B can block A's invocation, so cancel it before rotating A.
    secretsmanager.cancel_rotate_secret(SecretId=secret_b_arn)

    secret_a_stages_before = secretsmanager.describe_secret(SecretId=secret_a_arn)[
        "VersionIdsToStages"
    ]
    secret_a_original_version = [
        v for v, s in secret_a_stages_before.items() if "AWSCURRENT" in s
    ][0]

    # Positive control: rotating the CORRECTLY bound secret through the same function succeeds.
    secretsmanager.rotate_secret(
        SecretId=secret_a_arn,
        RotationLambdaARN=fn_arn,
        RotationRules={"AutomaticallyAfterDays": 1},
        RotateImmediately=True,
    )
    # Real AWS does not clear AWSPENDING from a version just because that same version also became
    # AWSCURRENT (after finishSecret succeeds, AWSPENDING can stay on the new AWSCURRENT version
    # indefinitely). The correct completion signal is that AWSCURRENT itself
    # moved to a new version id.
    _poll_until(
        lambda: [
            v
            for v, s in secretsmanager.describe_secret(SecretId=secret_a_arn)[
                "VersionIdsToStages"
            ].items()
            if "AWSCURRENT" in s
        ],
        lambda current_versions: current_versions != [secret_a_original_version],
        timeout_s=300.0,
        interval_s=5.0,
    )
    rotated = json.loads(
        secretsmanager.get_secret_value(
            SecretId=secret_a_arn, VersionStage="AWSCURRENT"
        )["SecretString"]
    )
    assert rotated["password"] != original_password


# ===== helpers =====

LAMBDA_SRC = r"""
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
    versions = metadata["VersionIdsToStages"]
    if token not in versions:
        raise ValueError(f"Secret version {token} has no stage for rotation of {arn}")
    if "AWSCURRENT" in versions[token]:
        return
    if "AWSPENDING" not in versions[token]:
        raise ValueError(f"Secret version {token} not AWSPENDING for {arn}")

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
        # instance's provisioning time (5-15 min) would dwarf the check's own budget. The
        # KeyError below is intentional when the secret is not RDS-bound (secret B).
        pending = json.loads(svc.get_secret_value(SecretId=arn, VersionId=token, VersionStage="AWSPENDING")["SecretString"])
        db_id = pending["dbInstanceIdentifier"]  # KeyError here if the secret is not RDS-bound
        rds = boto3.client("rds")
        rds.describe_db_instances(DBInstanceIdentifier=db_id)
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
"""


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


def _default_vpc_id(ctx) -> str | None:
    ec2 = ctx.client("ec2")
    resp = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])
    vpcs = resp.get("Vpcs", [])
    return vpcs[0]["VpcId"] if vpcs else None


def _create_db_subnet_group(ctx, vpc_id: str) -> str | None:
    ec2 = ctx.client("ec2")
    rds = ctx.client("rds")
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])[
        "Subnets"
    ]
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
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(
        lambda: _best_effort(lambda: rds.delete_db_subnet_group(DBSubnetGroupName=name))
    )
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


def _create_mysql_instance(
    ctx, db_id: str, master_password: str, subnet_group: str | None = None
) -> dict[str, Any]:
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
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    if subnet_group:
        kwargs["DBSubnetGroupName"] = subnet_group
    resp = rds.create_db_instance(**kwargs)
    ctx.on_cleanup(
        lambda: _best_effort(
            lambda: rds.delete_db_instance(
                DBInstanceIdentifier=db_id, SkipFinalSnapshot=True
            )
        )
    )
    return resp["DBInstance"]


def _create_secret_for_db(
    ctx,
    secretsmanager,
    secret_name: str,
    inst: dict[str, Any],
    username: str,
    password: str,
) -> str:
    secret_dict = {
        "engine": "mysql",
        "username": username,
        "password": password,
        "dbInstanceIdentifier": inst["DBInstanceIdentifier"],
    }
    resp = secretsmanager.create_secret(
        Name=secret_name,
        SecretString=json.dumps(secret_dict),
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(
        lambda: secretsmanager.delete_secret(
            SecretId=resp["ARN"], ForceDeleteWithoutRecovery=True
        )
    )
    return resp["ARN"]


def _create_lambda_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-rot-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: _best_effort(lambda: iam.delete_role(RoleName=role_name)))
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "logs:CreateLogGroup",
                    "logs:CreateLogStream",
                    "logs:PutLogEvents",
                ],
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
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(policy_doc),
    )
    ctx.on_cleanup(
        lambda: _best_effort(
            lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
        )
    )
    # IAM is eventually consistent: wait for the inline policy to actually be readable back
    # before handing the role to create_function, instead of guessing a fixed propagation delay.
    _poll_until(
        lambda: iam.get_role_policy(RoleName=role_name, PolicyName=policy_name).get(
            "PolicyName"
        ),
        lambda name: name == policy_name,
        timeout_s=30.0,
        interval_s=2.0,
    )
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
                Tags={"sim2real": "true"},
            )
            break
        except ClientError as err:
            if (
                err.response["Error"]["Code"] == "InvalidParameterValueException"
                and attempt < 7
            ):
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


def _add_invoke_permission(
    ctx, lam, function_name: str, statement_id: str = "AllowSecretsManagerInvoke"
) -> None:
    lam.add_permission(
        FunctionName=function_name,
        StatementId=statement_id,
        Action="lambda:InvokeFunction",
        Principal="secretsmanager.amazonaws.com",
    )
    ctx.on_cleanup(
        lambda: _best_effort(
            lambda: lam.remove_permission(
                FunctionName=function_name, StatementId=statement_id
            )
        )
    )


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
