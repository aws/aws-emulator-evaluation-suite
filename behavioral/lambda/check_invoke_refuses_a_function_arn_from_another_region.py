"""invoke-refuses-a-function-arn-from-another-region."""

from __future__ import annotations

import io
import json
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "invoke-refuses-a-function-arn-from-another-region"
GROUP = "compute"
SERVICES = ["lambda"]

ALT_REGION = "us-east-1"
CONTROL_INPUT = 6


@tags("axis:rejection", "cap:c3", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A function ARN naming another region does not resolve the local function of that name, while
    the correct ARN invokes it; the correct ARN sent through an other-region client is not found.
    """
    home_region = ctx.region
    assert home_region != ALT_REGION, (
        f"this check needs two distinct regions; harness region is {home_region!r} which equals the "
        f"alternate {ALT_REGION!r}. Change ALT_REGION"
    )
    lam = ctx.client("lambda")

    fn_name = _deploy(ctx, lam, """\
        def handler(event, context):
            return {"tripled": event["n"] * 3}
        """)
    account = ctx.account
    home_arn = f"arn:aws:lambda:{home_region}:{account}:function:{fn_name}"
    foreign_arn = f"arn:aws:lambda:{ALT_REGION}:{account}:function:{fn_name}"

    # --- Beat 1: positive control -- the function is live and its own ARN resolves it ---------------
    # First, so a later refusal cannot be confused with a function that was never usable.
    resp = lam.invoke(
        FunctionName=home_arn,
        InvocationType="RequestResponse",
        Payload=json.dumps({"n": CONTROL_INPUT}).encode(),
    )
    assert resp.get("FunctionError") is None, (
        f"the function's own ARN must invoke cleanly; got FunctionError={resp.get('FunctionError')!r}"
    )
    assert json.loads(resp["Payload"].read()) == {"tripled": CONTROL_INPUT * 3}, (
        "the control invoke must return the handler's computed output"
    )

    # --- Beat 2: the same name under a FOREIGN region in the ARN must not resolve ------------------
    # The function does not exist in ALT_REGION, so real AWS cannot find it. A target that ignores the
    # ARN's region component resolves the local function and succeeds here.
    error = _client_error(
        lambda: lam.invoke(
            FunctionName=foreign_arn,
            InvocationType="RequestResponse",
            Payload=json.dumps({"n": CONTROL_INPUT}).encode(),
        )
    )
    code = error.get("Code")
    assert code == "ResourceNotFoundException", (
        f"an ARN naming {ALT_REGION!r} must not resolve a function that exists only in "
        f"{home_region!r}; expected ResourceNotFoundException, got {code!r}: "
        f"{error.get('Message')!r}"
    )
    expected = f"Functions from '{ALT_REGION}' are not reachable in this region ('{home_region}')"
    assert error.get("Message") == expected, (
        f"expected message {expected!r}, got {error.get('Message')!r}"
    )

    # --- Beat 3: and the client's own region is honoured too --------------------------------------
    # The mirror case: the correct ARN, issued through a client configured for the
    # OTHER region. The function is not in that region, so it must not be found.
    alt_client = ctx.client("lambda", region=ALT_REGION)
    alt_error = _client_error(
        lambda: alt_client.invoke(
            FunctionName=fn_name,
            InvocationType="RequestResponse",
            Payload=json.dumps({"n": CONTROL_INPUT}).encode(),
        )
    )
    assert alt_error.get("Code") == "ResourceNotFoundException", (
        f"a client configured for {ALT_REGION!r} must not reach a function that exists only in "
        f"{home_region!r}; got {alt_error.get('Code')!r}: {alt_error.get('Message')!r}"
    )
    alt_expected = f"Function not found: arn:aws:lambda:{ALT_REGION}:{account}:function:{fn_name}:$LATEST"
    assert alt_error.get("Message") == alt_expected, (
        f"expected message {alt_expected!r}, got {alt_error.get('Message')!r}"
    )


def _make_zip(code: str, filename: str = "index.py") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, textwrap.dedent(code))
    return buf.getvalue()


_EXEC_ROLES = {}


def _exec_role_arn(ctx):
    """An execution role this check creates, shared by every function it deploys."""
    cached = _EXEC_ROLES.get(id(ctx))
    if cached is not None and cached[0] is ctx:
        return cached[1]
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    _EXEC_ROLES[id(ctx)] = (ctx, arn)
    return arn


def _create_function(lam, kwargs, timeout_s=90):
    """CreateFunction, retried while a freshly created role is not yet assumable by Lambda."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            propagating = (
                err.get("Code") == "InvalidParameterValueException"
                and "cannot be assumed by Lambda" in err.get("Message", "")
            )
            if not propagating or time.monotonic() >= deadline:
                raise
            time.sleep(3.0)


def _cleanup_fn(ctx, lam, name: str) -> None:
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


def _deploy(ctx, lam, code: str) -> str:
    name = ctx.unique_name("sim2real-behav-region-fn-")
    _create_function(lam, dict(
        FunctionName=name,
        Runtime="python3.12",
        Handler="index.handler",
        Role=_exec_role_arn(ctx),
        Code={"ZipFile": _make_zip(code)},
        MemorySize=128,
        Timeout=30,
        Tags={"sim2real:managed": "true"},
    ))
    ctx.on_cleanup(lambda: _cleanup_fn(ctx, lam, name))
    deadline = time.monotonic() + 120.0
    last = None
    while time.monotonic() < deadline:
        last = lam.get_function_configuration(FunctionName=name)
        if last["State"] == "Failed":
            raise AssertionError(f"function {name} entered Failed: {last.get('StateReason')!r}")
        if last["State"] == "Active":
            return name
        time.sleep(1.0)
    raise AssertionError(f"function {name} did not reach Active within 120s (last={last!r})")


def _client_error(fn) -> dict:
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because a target
    ACCEPTING a request real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
