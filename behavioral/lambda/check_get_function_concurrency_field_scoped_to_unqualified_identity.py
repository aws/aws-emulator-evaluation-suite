"""get-function-concurrency-field-scoped-to-unqualified-identity."""
from __future__ import annotations

import io
import json
import textwrap
import time
import zipfile

from behavioral_harness import tags

CHECK = "get-function-concurrency-field-scoped-to-unqualified-identity"
GROUP = "concurrency"
SERVICES = ["lambda"]


def _make_zip(code, filename="index.py"):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, textwrap.dedent(code))
    return buf.getvalue()


_LAMBDA_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
                   "Action": "sts:AssumeRole"}],
})
_BASIC_EXEC = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"


def _create_role(ctx):
    """An execution role this check creates (Lambda trust + basic logging), removed at cleanup."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-exec-")
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=_LAMBDA_TRUST,
                          Tags=[{"Key": "sim2real:managed", "Value": "true"}])["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.attach_role_policy(RoleName=name, PolicyArn=_BASIC_EXEC)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=_BASIC_EXEC))
    return arn


def _create_function(lam, **kwargs):
    """CreateFunction, retrying only the fresh-role refusal ("cannot be assumed") for at most 90 s."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 90.0
    while True:
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            if "cannot be assumed" in str(exc) and time.monotonic() < deadline:
                time.sleep(3.0)  # a role created seconds ago is not yet assumable by Lambda
                continue
            raise


def _cleanup_fn(ctx, lam, name):
    """Delete the function and its log group; an already-absent one is done, anything else raises."""
    from botocore.exceptions import ClientError

    for delete in (lambda: lam.delete_function(FunctionName=name),
                   lambda: ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{name}")):
        try:
            delete()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise


def _wait_active(lam, fn, timeout_s=90):
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


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetFunction's Concurrency tracks the reserved value (including 0, and cleared on delete) only
    for an unqualified name or ARN; any qualified reference omits it, since reserved concurrency
    belongs to the function, not a version.
    """
    lam = ctx.client("lambda")
    fn = ctx.unique_name("sim2real-behav-fn-")
    _create_function(lam,
        FunctionName=fn, Runtime="python3.12", Handler="index.handler",
        Role=_create_role(ctx), Code={"ZipFile": _make_zip("def handler(e, c): return e")},
        MemorySize=128, Timeout=10,
        Tags={"sim2real:managed": "true"},
    )
    ctx.on_cleanup(lambda: _cleanup_fn(ctx, lam, fn))
    _wait_active(lam, fn)

    unset = lam.get_function(FunctionName=fn)
    assert unset.get("Concurrency") is None, (
        f"a function with no reserved concurrency set should omit Concurrency, "
        f"got {unset.get('Concurrency')!r}"
    )

    function_arn = unset["Configuration"]["FunctionArn"]
    version = lam.publish_version(FunctionName=fn)["Version"]
    lam.create_alias(FunctionName=fn, Name="live", FunctionVersion=version)

    for reservation in (2, 7, 0):
        put = lam.put_function_concurrency(FunctionName=fn, ReservedConcurrentExecutions=reservation)
        assert put["ReservedConcurrentExecutions"] == reservation, (
            f"PutFunctionConcurrency({reservation}) should echo {reservation}, "
            f"got {put.get('ReservedConcurrentExecutions')!r}"
        )

        by_name = lam.get_function(FunctionName=fn)
        assert by_name.get("Concurrency") is not None, (
            f"GetFunction(unqualified name) after Put({reservation}) should carry Concurrency, got None"
        )
        assert by_name["Concurrency"]["ReservedConcurrentExecutions"] == reservation, (
            f"GetFunction(unqualified name).Concurrency should read back {reservation}, "
            f"got {by_name['Concurrency']['ReservedConcurrentExecutions']!r}"
        )
        assert by_name["Configuration"]["FunctionName"] == fn, by_name["Configuration"]["FunctionName"]
        assert by_name["Code"]["Location"], "GetFunction.Code.Location must be populated"

        by_arn = lam.get_function(FunctionName=function_arn)
        assert by_arn["Concurrency"]["ReservedConcurrentExecutions"] == reservation, (
            f"GetFunction(unqualified ARN).Concurrency should read back {reservation}, "
            f"got {by_arn['Concurrency']!r}"
        )

        for qualifier in ("$LATEST", version, "live"):
            qualified = lam.get_function(FunctionName=fn, Qualifier=qualifier)
            assert qualified.get("Concurrency") is None, (
                f"GetFunction(qualifier={qualifier!r}) must omit Concurrency even though "
                f"reserved concurrency {reservation} is set, got {qualified.get('Concurrency')!r}"
            )
            for reference in (f"{fn}:{qualifier}", f"{function_arn}:{qualifier}"):
                by_reference = lam.get_function(FunctionName=reference)
                assert by_reference.get("Concurrency") is None, (
                    f"GetFunction(FunctionName={reference!r}) must omit Concurrency, "
                    f"got {by_reference.get('Concurrency')!r}"
                )

    lam.delete_function_concurrency(FunctionName=fn)
    cleared = lam.get_function(FunctionName=fn)
    assert cleared.get("Concurrency") is None, (
        f"after DeleteFunctionConcurrency, GetFunction(unqualified) should omit Concurrency, "
        f"got {cleared.get('Concurrency')!r}"
    )
    cleared_qualified = lam.get_function(FunctionName=fn, Qualifier=version)
    assert cleared_qualified.get("Concurrency") is None, (
        f"a qualified GetFunction should still omit Concurrency after delete, "
        f"got {cleared_qualified.get('Concurrency')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
