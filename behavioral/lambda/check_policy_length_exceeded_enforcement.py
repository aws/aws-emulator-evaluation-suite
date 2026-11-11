"""policy-length-exceeded-enforcement."""

from __future__ import annotations

import io
import json
import textwrap
import time
import uuid
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "policy-length-exceeded-enforcement"
GROUP = 'permissions'
SERVICES = ['lambda']

HANDLER_V1 = "def handler(event, context): return {'marker': 'v1', 'echo': event}"


def _make_zip(code, filename="index.py"):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, textwrap.dedent(code))
    return buf.getvalue()


_ROLES: dict = {}
_BASIC_EXEC = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
_ROLE_NOT_READY = "The role defined for the function cannot be assumed by Lambda."


def _role_arn(ctx):
    """Create this run's own Lambda execution role (once per run) and return its ARN."""
    if id(ctx) in _ROLES:
        return _ROLES[id(ctx)]
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.attach_role_policy(RoleName=name, PolicyArn=_BASIC_EXEC)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=_BASIC_EXEC))
    _ROLES[id(ctx)] = arn
    return arn


def _create_function(lam, **kwargs):
    """CreateFunction, retried while a freshly created execution role is still propagating."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 90
    while True:
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            not_ready = (err.get("Code") == "InvalidParameterValueException"
                         and err.get("Message") == _ROLE_NOT_READY)
            if not not_ready or time.monotonic() > deadline:
                raise
            time.sleep(3)


def _account(ctx):
    return ctx.account


def _cleanup_fn(ctx, lam, name):
    try:
        lam.delete_function(FunctionName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    try:
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{name}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _wait_active(lam, fn, timeout_s=60):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = lam.get_function_configuration(FunctionName=fn)
        if last["State"] == "Failed":
            raise AssertionError(f"Function {fn} entered Failed: {last.get('StateReason')}")
        if last["State"] == "Active":
            return
        time.sleep(1.0)
    raise AssertionError(f"{fn} Active not met within {timeout_s}s. Last: {last!r}")


def _deploy_function(ctx, lam, code, *, name=None):
    name = name or ctx.unique_name("sim2real-behav-fn-")
    _create_function(lam,
        FunctionName=name,
        Runtime="python3.12",
        Handler="index.handler",
        Role=_role_arn(ctx),
        Code={"ZipFile": _make_zip(code)},
        MemorySize=128,
        Timeout=30,
        Tags={"sim2real": "policy-length-exceeded-enforcement"},
    )
    ctx.on_cleanup(lambda: _cleanup_fn(ctx, lam, name))
    _wait_active(lam, name)
    return name


def _error(fn):
    """Run *fn*, which AWS must refuse; return the refusal's (code, message)."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded with {result!r}")


def _publish_layer(ctx, lam):
    layer_name = ctx.unique_name("sim2real-behav-layer-")
    value = f"sim2real-{uuid.uuid4().hex[:12]}"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("python/sim2real_marker_module.py", f"VALUE = {value!r}\n")
    resp = lam.publish_layer_version(
        LayerName=layer_name, Content={"ZipFile": buf.getvalue()},
        CompatibleRuntimes=["python3.12"],
    )
    version = resp["Version"]
    ctx.on_cleanup(lambda: lam.delete_layer_version(LayerName=layer_name, VersionNumber=version))
    return layer_name, version


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Growing a function or layer-version policy past 20 KB via
    AddPermission/AddLayerVersionPermission is PolicyLengthExceededException; an oversized
    PutResourcePolicy is a ValidationException. No rejected write is persisted.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/gettingstarted-limits.html
    """
    lam = ctx.client("lambda")
    account = _account(ctx)

    fn = _deploy_function(ctx, lam, HANDLER_V1)
    fn_arn = lam.get_function_configuration(FunctionName=fn)["FunctionArn"]

    # PutResourcePolicy is absent from older botocore builds, so that path runs only when present.
    if hasattr(lam, "put_resource_policy"):
        # Positive control: a small policy is accepted, so the rejection below is size-specific.
        small_policy = json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Sid": "sim2realbehavpospolicy",
                "Effect": "Allow",
                "Principal": {"AWS": account},
                "Action": "lambda:GetFunction",
                "Resource": fn_arn,
            }],
        })
        lam.put_resource_policy(ResourceArn=fn_arn, Policy=small_policy)
        stored_small = json.loads(lam.get_resource_policy(ResourceArn=fn_arn)["Policy"])
        assert [s["Sid"] for s in stored_small["Statement"]] == ["sim2realbehavpospolicy"], (
            f"expected the positive-control policy to round-trip, got {stored_small!r}"
        )

        statements = [
            {
                "Sid": f"sim2realbehavpad{i:04d}" + "x" * 60,
                "Effect": "Allow",
                "Principal": {"AWS": account},
                "Action": "lambda:GetFunction",
                "Resource": fn_arn,
            }
            for i in range(80)
        ]
        big_policy = json.dumps({"Version": "2012-10-17", "Statement": statements})
        assert len(big_policy) > 20 * 1024, f"test policy only {len(big_policy)} bytes, need > 20KB"
        put_code, put_msg = _error(lambda: lam.put_resource_policy(ResourceArn=fn_arn, Policy=big_policy))
        assert put_code == "ValidationException", (
            f"expected ValidationException from an oversized single-call PutResourcePolicy, got {put_code}"
        )
        expected_put_msg = (
            f"1 validation error detected: Value '{big_policy}' at 'policy' failed to satisfy "
            f"constraint: Member must have length less than or equal to 20480"
        )
        assert put_msg == expected_put_msg, f"expected the exact oversized-policy message, got {put_msg!r}"

        stored_after = json.loads(lam.get_resource_policy(ResourceArn=fn_arn)["Policy"])
        assert [s["Sid"] for s in stored_after["Statement"]] == ["sim2realbehavpospolicy"], (
            f"expected the rejected oversized PutResourcePolicy to leave the prior policy "
            f"untouched, got {stored_after!r}"
        )
        lam.delete_resource_policy(ResourceArn=fn_arn)

    # Each AddPermission is small; only the cumulative stored policy exceeds 20 KB.
    add_perm_code = None
    added = 0
    for _i in range(80):
        topic_name = ("sim2real-behav-topic-" + uuid.uuid4().hex + "-" + "x" * 200)[:256]
        source_arn = f"arn:aws:sns:{ctx.region}:{account}:{topic_name}"
        try:
            lam.add_permission(
                FunctionName=fn,
                StatementId=("sim2realbehavap" + uuid.uuid4().hex)[:100],
                Action="lambda:InvokeFunction",
                Principal="sns.amazonaws.com",
                SourceArn=source_arn,
            )
            added += 1
        except ClientError as exc:
            add_perm_code = exc.response.get("Error", {}).get("Code")
            break
    assert added > 0, "expected at least one AddPermission statement to succeed before the limit"
    # Message not asserted: its "final policy size (N)" is an internal measure, not the doc length.
    assert add_perm_code == "PolicyLengthExceededException", (
        f"expected PolicyLengthExceededException from AddPermission after {added} statements, got {add_perm_code}"
    )

    fn_policy = json.loads(lam.get_policy(FunctionName=fn)["Policy"])
    fn_statement_count = len(fn_policy.get("Statement", []))
    assert fn_statement_count == added, (
        f"expected exactly {added} AddPermission statements to have taken effect (the rejected "
        f"one must not persist), found {fn_statement_count}"
    )

    layer_name, version = _publish_layer(ctx, lam)
    add_layer_perm_code = None
    layer_added = 0
    for i in range(150):
        try:
            lam.add_layer_version_permission(
                LayerName=layer_name,
                VersionNumber=version,
                StatementId=("sim2realbehavlp" + uuid.uuid4().hex)[:100],
                Action="lambda:GetLayerVersion",
                Principal=account,
            )
            layer_added += 1
        except ClientError as exc:
            add_layer_perm_code = exc.response.get("Error", {}).get("Code")
            break
    assert layer_added > 0, "expected at least one AddLayerVersionPermission statement to succeed"
    # Message not asserted: same internal policy-size figure as the AddPermission refusal.
    assert add_layer_perm_code == "PolicyLengthExceededException", (
        f"expected PolicyLengthExceededException from AddLayerVersionPermission after "
        f"{layer_added} statements, got {add_layer_perm_code}"
    )

    layer_policy = json.loads(
        lam.get_layer_version_policy(LayerName=layer_name, VersionNumber=version)["Policy"]
    )
    layer_statement_count = len(layer_policy.get("Statement", []))
    assert layer_statement_count == layer_added, (
        f"expected exactly {layer_added} AddLayerVersionPermission statements to have taken "
        f"effect (the rejected one must not persist), found {layer_statement_count}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
