"""empty-vs-absent-property-distinguished."""
from __future__ import annotations

import base64
import io
import json
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "empty-vs-absent-property-distinguished"
GROUP = "representation"
SERVICES = ["cloudcontrol"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A Lambda function created with Environment {"Variables": {}} reports an Environment block
    on GetResource, while one that omits Environment reports none.
    """
    cc = ctx.client("cloudcontrol")
    iam = ctx.client("iam")

    role_name = ctx.unique_name("sim2real-behav-role-")
    trust_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "lambda.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust_policy,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("index.py", "def handler(event, context):\n    return {'ok': True}\n")
    code_zip = base64.b64encode(buf.getvalue()).decode("ascii")

    name_empty = ctx.unique_name("sim2real-behav-envempty-")
    name_absent = ctx.unique_name("sim2real-behav-envabsent-")

    tags = [{"Key": "sim2real:managed", "Value": "true"}]
    desired_empty = json.dumps(
        {
            "FunctionName": name_empty,
            "Runtime": "python3.12",
            "Handler": "index.handler",
            "Role": role_arn,
            "Code": {"ZipFile": code_zip},
            "Environment": {"Variables": {}},
            "Tags": tags,
        }
    )
    desired_absent = json.dumps(
        {
            "FunctionName": name_absent,
            "Runtime": "python3.12",
            "Handler": "index.handler",
            "Role": role_arn,
            "Code": {"ZipFile": code_zip},
            "Tags": tags,
        }
    )

    pe_empty = _create_with_role_propagation_retry(ctx, cc, desired_empty)
    id_empty = pe_empty["Identifier"]
    ctx.on_cleanup(lambda: _delete_resource(ctx, "AWS::Lambda::Function", id_empty))

    pe_absent = _create_with_role_propagation_retry(ctx, cc, desired_absent)
    id_absent = pe_absent["Identifier"]
    ctx.on_cleanup(lambda: _delete_resource(ctx, "AWS::Lambda::Function", id_absent))

    got_empty = cc.get_resource(TypeName="AWS::Lambda::Function", Identifier=id_empty)
    props_empty = json.loads(got_empty["ResourceDescription"]["Properties"])
    got_absent = cc.get_resource(TypeName="AWS::Lambda::Function", Identifier=id_absent)
    props_absent = json.loads(got_absent["ResourceDescription"]["Properties"])

    assert "Environment" in props_empty, (
        f"expected an explicit empty Environment block to be reported, got {props_empty}"
    )
    assert props_empty["Environment"].get("Variables", {}) == {}, (
        f"expected the explicit empty Environment block to report Variables == {{}}, "
        f"got {props_empty['Environment']!r}"
    )
    assert "Environment" not in props_absent, (
        f"expected Environment to be entirely absent when never configured, got {props_absent}"
    )


def _create_with_role_propagation_retry(ctx, cc, desired_state, attempts=6, delay_s=8.0):
    """Create, retrying only a FAILED outcome naming the role while its IAM trust propagates."""
    pe = None
    for _ in range(attempts):
        create = cc.create_resource(TypeName="AWS::Lambda::Function", DesiredState=desired_state)
        pe = _wait_terminal(ctx, create["ProgressEvent"]["RequestToken"], timeout_s=90.0)
        role_refused = "role" in (pe.get("StatusMessage") or "").lower()
        if not (pe["OperationStatus"] == "FAILED" and role_refused):
            break
        time.sleep(delay_s)
    assert pe["OperationStatus"] == "SUCCESS", (
        f"cloudcontrol create ended in {pe['OperationStatus']}: "
        f"{pe.get('StatusMessage')} / {pe.get('ErrorCode')}"
    )
    return pe


def _wait_terminal(ctx, request_token, timeout_s=180.0, interval_s=2.0):
    """Poll to any terminal OperationStatus and return that ProgressEvent; raises on timeout."""
    cc = ctx.client("cloudcontrol")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        pe = cc.get_resource_request_status(RequestToken=request_token)["ProgressEvent"]
        last = pe
        if pe["OperationStatus"] in ("SUCCESS", "FAILED", "CANCEL_COMPLETE"):
            return pe
        time.sleep(interval_s)
    raise AssertionError(f"cloudcontrol operation did not reach terminal state within {timeout_s}s: {last}")


def _wait_for_operation(ctx, request_token, timeout_s=180.0, interval_s=2.0):
    cc = ctx.client("cloudcontrol")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = cc.get_resource_request_status(RequestToken=request_token)
        pe = resp["ProgressEvent"]
        last = pe
        status = pe["OperationStatus"]
        if status == "SUCCESS":
            return pe
        if status in ("FAILED", "CANCEL_COMPLETE"):
            raise AssertionError(
                f"cloudcontrol operation ended in {status}: "
                f"{pe.get('StatusMessage')} / {pe.get('ErrorCode')}"
            )
        time.sleep(interval_s)
    raise AssertionError(f"cloudcontrol operation did not reach terminal state within {timeout_s}s: {last}")


def _delete_resource(ctx, type_name, identifier):
    cc = ctx.client("cloudcontrol")
    try:
        delete = cc.delete_resource(TypeName=type_name, Identifier=identifier)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ResourceNotFoundException",
            "TypeNotFoundException",
        ):
            raise
        return
    _wait_for_operation(ctx, delete["ProgressEvent"]["RequestToken"], timeout_s=120.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
