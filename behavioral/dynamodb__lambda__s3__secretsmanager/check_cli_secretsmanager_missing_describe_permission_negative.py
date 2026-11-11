"""cli-secretsmanager-missing-describe-permission-negative."""
from __future__ import annotations

import io
import json
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "cli-secretsmanager-missing-describe-permission-negative"
GROUP = "permission-boundary"
SERVICES = ["dynamodb", "lambda", "s3", "secretsmanager"]


@tags("axis:rejection", "cap:c2", "cap:c3", "cap:c7", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Lambda role without secretsmanager:DescribeSecret cannot complete a workflow that
    calls DescribeSecret to fetch rotation metadata before writing a DynamoDB record: the
    call is denied, no item is written, and granting the permission unblocks it."""
    sm = ctx.client("secretsmanager")
    ddb = ctx.client("dynamodb")
    iam = ctx.client("iam")

    secret_name = ctx.unique_name("sim2real-desc-secret-")
    created = sm.create_secret(
        Name=secret_name, SecretString="config-value", Tags=[{"Key": "sim2real", "Value": CHECK}]
    )
    secret_arn = created["ARN"]
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=secret_arn, ForceDeleteWithoutRecovery=True))

    table_name = ctx.unique_name("sim2real-desc-table-")
    ddb.create_table(
        TableName=table_name,
        AttributeDefinitions=[{"AttributeName": "secret_id", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "secret_id", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table_name))
    _wait_table_active(ctx, table_name)

    # Role has dynamodb:PutItem but NOT secretsmanager:DescribeSecret.
    role_arn = _create_lambda_role(
        ctx,
        [
            {
                "Effect": "Allow",
                "Action": ["dynamodb:PutItem", "dynamodb:GetItem"],
                "Resource": f"arn:aws:dynamodb:{ctx.region}:*:table/{table_name}",
            }
        ],
    )

    handler_code = (
        "import boto3, os\n"
        "from botocore.exceptions import ClientError\n"
        "def handler(event, context):\n"
        "    sm = boto3.client('secretsmanager')\n"
        "    ddb = boto3.client('dynamodb')\n"
        "    sid = os.environ['SECRET_ID']\n"
        "    table = os.environ['TABLE_NAME']\n"
        "    try:\n"
        "        desc = sm.describe_secret(SecretId=sid)\n"
        "        ddb.put_item(TableName=table, Item={'secret_id': {'S': sid}, 'name': {'S': desc['Name']}})\n"
        "        return {'ok': True}\n"
        "    except ClientError as e:\n"
        "        return {'ok': False, 'code': e.response['Error']['Code']}\n"
    )
    fn_name = _create_function(
        ctx, role_arn, handler_code, env_vars={"SECRET_ID": secret_arn, "TABLE_NAME": table_name}
    )

    _, body = _invoke(ctx, fn_name)
    assert body["ok"] is False, f"expected the invocation to be denied, got {body}"
    assert body["code"] == "AccessDeniedException", body

    item = ddb.get_item(TableName=table_name, Key={"secret_id": {"S": secret_arn}}).get("Item")
    assert item is None, f"item should not exist without DescribeSecret permission, got {item}"

    # Positive control: grant DescribeSecret and retry the identical call.
    policy_name = f"{fn_name}-describe-grant"
    iam_role_name = role_arn.split("/")[-1]
    iam.put_role_policy(
        RoleName=iam_role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": "secretsmanager:DescribeSecret", "Resource": secret_arn}
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=iam_role_name, PolicyName=policy_name))

    # IAM policy propagation is eventually consistent: retry the identical call on a bounded
    # deadline rather than sleeping blind before the first attempt.
    deadline = time.monotonic() + 45.0
    body_after = None
    while time.monotonic() < deadline:
        _, body_after = _invoke(ctx, fn_name)
        if body_after.get("ok") is True:
            break
        time.sleep(3)
    assert body_after is not None and body_after["ok"] is True, body_after

    item_after = ddb.get_item(TableName=table_name, Key={"secret_id": {"S": secret_arn}}).get("Item")
    assert (
        item_after is not None and item_after["secret_id"]["S"] == secret_arn
    ), f"expected item with secret_id={secret_arn!r}, got {item_after}"


def _wait_table_active(ctx, table_name, timeout_s=60.0):
    ddb = ctx.client("dynamodb")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        desc = ddb.describe_table(TableName=table_name)["Table"]
        if desc["TableStatus"] == "ACTIVE":
            return
        time.sleep(2)
    raise AssertionError(f"table {table_name} never became ACTIVE")


def _make_zip(handler_code: str, filename="index.py") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, handler_code)
    return buf.getvalue()


def _create_lambda_role(ctx, policy_statements, role_name=None):
    iam = ctx.client("iam")
    role_name = role_name or ctx.unique_name("sim2real-lam-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    basic_policy = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=basic_policy)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=basic_policy))
    if policy_statements:
        policy_name = f"{role_name}-inline"
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName=policy_name,
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": policy_statements}),
        )
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _create_function(ctx, role_arn, handler_code, handler="index.handler", env_vars=None, timeout=30):
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-fn-")
    zip_bytes = _make_zip(handler_code)
    kwargs = dict(
        FunctionName=name,
        Runtime="python3.12",
        Role=role_arn,
        Handler=handler,
        Code={"ZipFile": zip_bytes},
        Timeout=timeout,
        Publish=False,
        Tags={"sim2real": CHECK},
    )
    if env_vars:
        kwargs["Environment"] = {"Variables": env_vars}
    last_err = None
    for _ in range(8):
        try:
            ctx.on_cleanup(lambda _n=name: _delete_lambda_log_group(ctx, _n))
            lam.create_function(**kwargs)
            break
        except lam.exceptions.InvalidParameterValueException as e:
            # The role IAM just created may not yet be assumable by Lambda; retry on a
            # bounded deadline instead of sleeping blind before the first attempt.
            last_err = e
            time.sleep(5)
    else:
        raise last_err
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    _wait_for_active(ctx, name)
    return name


def _wait_for_active(ctx, name, timeout_s=60.0):
    lam = ctx.client("lambda")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        cfg = lam.get_function_configuration(FunctionName=name)
        if cfg["State"] == "Active":
            return
        time.sleep(2)
    raise AssertionError(f"function {name} never became Active")


def _invoke(ctx, name, payload=None):
    lam = ctx.client("lambda")
    resp = lam.invoke(
        FunctionName=name, Payload=json.dumps(payload or {}).encode(), InvocationType="RequestResponse"
    )
    body = json.loads(resp["Payload"].read())
    return resp, body


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
