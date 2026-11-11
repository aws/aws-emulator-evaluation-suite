"""lambda-sesv2-create-contact-list-missing-permission-negative."""
from __future__ import annotations

import io
import json
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "lambda-sesv2-create-contact-list-missing-permission-negative"
GROUP = "permission-boundary"
SERVICES = ["lambda", "sesv2"]

_CODE = '''
import boto3
from botocore.exceptions import ClientError

def handler(event, context):
    client = boto3.client("sesv2")
    try:
        client.create_contact_list(ContactListName=event["name"])
    except ClientError as exc:
        return {
            "success": False,
            "error_code": exc.response["Error"]["Code"],
            "error_message": exc.response["Error"].get("Message", ""),
        }
    return {"success": True}
'''


@tags("resource:account-singleton:sesv2-contact-list", "axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Lambda role lacking ses:CreateContactList is denied and no list is created;
    a sibling role that has the permission still succeeds (in-file positive control)."""
    sesv2 = ctx.client("sesv2")
    denied_name = ctx.unique_name("sim2real-sesv2lam-cl-denied-")
    allowed_name = ctx.unique_name("sim2real-sesv2lam-cl-allowed-")
    ctx.on_cleanup(lambda: _ignore(lambda: sesv2.delete_contact_list(ContactListName=allowed_name)))

    role_no_perm = _create_lambda_role(ctx, None)
    fn_no_perm = _create_lambda_function(ctx, role_no_perm, _CODE)
    body = _invoke_lambda(ctx, fn_no_perm, {"name": denied_name})
    assert body["success"] is False, body
    assert body["error_code"] == "AccessDeniedException", f"expected AccessDeniedException, got {body}"
    expected_denial = _access_denied_message(
        ctx, role_no_perm, fn_no_perm, "ses:CreateContactList", f"contact-list/{denied_name}"
    )
    assert body["error_message"] == expected_denial, f"{body!r} != {expected_denial!r}"

    code, message = _error(lambda: sesv2.get_contact_list(ContactListName=denied_name))
    assert code == "NotFoundException", f"expected NotFoundException for unwritten contact list, got {code}"
    expected_message = f"List with name: {denied_name} doesn't exist."
    assert message == expected_message, f"{message!r} != {expected_message!r}"

    role_with_perm = _create_lambda_role(
        ctx, [{"Effect": "Allow", "Action": "ses:CreateContactList", "Resource": "*"}]
    )
    fn_with_perm = _create_lambda_function(ctx, role_with_perm, _CODE)
    control_body = _invoke_lambda(ctx, fn_with_perm, {"name": allowed_name})
    assert control_body["success"] is True, control_body
    resp = sesv2.get_contact_list(ContactListName=allowed_name)
    assert resp["ContactListName"] == allowed_name, f"expected {allowed_name}, got {resp.get('ContactListName')}"


def _ignore(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _error(fn) -> tuple[str, str]:
    """(code, message) of the ClientError fn raises; an unexpected success raises."""
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


def _access_denied_message(ctx, role_arn: str, function_name: str, action: str, resource: str) -> str:
    """The IAM denial SESv2 returns to a Lambda whose execution role has no grant for action."""
    role_name = role_arn.rsplit("/", 1)[-1]
    return (
        f"User: arn:aws:sts::{ctx.account}:assumed-role/{role_name}/{function_name} is not "
        f"authorized to perform: {action} on resource: "
        f"arn:aws:ses:{ctx.region}:{ctx.account}:{resource} "
        f"because no identity-based policy allows the {action} action"
    )


def _lambda_zip_bytes(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", code)
    return buf.getvalue()


def _create_lambda_role(ctx, inline_statements):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-sesv2lam-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    if inline_statements:
        policy_name = f"{role_name}-policy"
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName=policy_name,
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": inline_statements}),
        )
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _create_lambda_function(ctx, role_arn, code):
    lam = ctx.client("lambda")
    fn_name = ctx.unique_name("sim2real-sesv2lam-fn-")
    zip_bytes = _lambda_zip_bytes(code)
    deadline = time.monotonic() + 90
    while True:
        try:
            lam.create_function(
                FunctionName=fn_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": zip_bytes},
                Timeout=30,
                MemorySize=128,
                Tags={"sim2real-check": CHECK},
            )
            break
        except lam.exceptions.InvalidParameterValueException:
            if time.monotonic() > deadline:
                raise
            time.sleep(3)
    ctx.on_cleanup(lambda: _delete_function_log_group(ctx, fn_name))
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn_name))
    lam.get_waiter("function_active_v2").wait(FunctionName=fn_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    return fn_name


def _invoke_lambda(ctx, fn_name, payload):
    lam = ctx.client("lambda")
    resp = lam.invoke(FunctionName=fn_name, Payload=json.dumps(payload).encode("utf-8"))
    body = json.loads(resp["Payload"].read())
    if resp.get("FunctionError"):
        raise AssertionError(f"lambda invocation errored: {body}")
    return body


def _delete_function_log_group(ctx, function_name: str) -> None:
    """Delete the log group Lambda creates for a function on its first invocation and never
    deletes. Registered before the function's own teardown, so it runs after the function is
    gone; the service can still create the group from logs it delivers a few seconds later, so
    the group must stay absent across two reads 5 s apart. Only an already-absent group is
    tolerated; a group still present after 30 s raises."""
    import time

    from botocore.exceptions import ClientError

    logs = ctx.client("logs")
    group = f"/aws/lambda/{function_name}"

    def present() -> bool:
        found = logs.describe_log_groups(logGroupNamePrefix=group)["logGroups"]
        return any(g["logGroupName"] == group for g in found)

    deadline = time.monotonic() + 30.0
    while True:
        try:
            logs.delete_log_group(logGroupName=group)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        time.sleep(5.0)
        if not present():
            time.sleep(5.0)
            if not present():
                return
        if time.monotonic() >= deadline:
            raise RuntimeError(f"log group {group} still present 30 s after delete_log_group")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
