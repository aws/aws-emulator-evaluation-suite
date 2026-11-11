"""list-functions-pagination-order."""

from __future__ import annotations

import io
import json
import textwrap
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "list-functions-pagination-order"
GROUP = 'pagination'
SERVICES = ['lambda']


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


def _cleanup_fn(ctx, lam, name):
    try:
        lam.delete_function_url_config(FunctionName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
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


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListFunctions pagination tokens yield a stable total ordering with no duplicates or
    omissions across pages."""
    lam = ctx.client("lambda")
    role = _role_arn(ctx)
    fn_names = [ctx.unique_name(f"sim2real-behav-pg-{i}-") for i in range(6)]
    for name in fn_names:
        _create_function(lam,
            FunctionName=name,
            Runtime="python3.12",
            Handler="index.handler",
            Role=role,
            Code={"ZipFile": _make_zip("def handler(e, c): return e")},
            MemorySize=128,
            Timeout=30,
            Tags={"sim2real:managed": "true"},
        )
        ctx.on_cleanup(lambda n=name: _cleanup_fn(ctx, lam, n))
    for name in fn_names:
        _wait_active(lam, name)

    def _paginate_full():
        names = []
        marker = None
        pages = 0
        while True:
            kwargs = {"MaxItems": 2}
            if marker:
                kwargs["Marker"] = marker
            page = lam.list_functions(**kwargs)
            assert len(page["Functions"]) <= 2, (
                f"expected ListFunctions to honor MaxItems=2 per page, got "
                f"{len(page['Functions'])} entries in one page"
            )
            pages += 1
            names.extend(f["FunctionName"] for f in page["Functions"])
            marker = page.get("NextMarker")
            if not marker:
                break
        assert pages > 1, (
            f"expected the {len(fn_names)} functions we created to force more than one "
            f"MaxItems=2 page, got a single page — MaxItems is not being honored"
        )
        return names

    pass1 = _paginate_full()
    pass2 = _paginate_full()

    assert len(pass1) == len(set(pass1)), "ListFunctions pagination must not return duplicate entries"
    ours_1 = [n for n in pass1 if n in fn_names]
    ours_2 = [n for n in pass2 if n in fn_names]
    assert set(ours_1) == set(fn_names), f"expected every created function present across pages, got {ours_1}"
    assert ours_1 == ours_2, (
        f"expected our functions' relative order to be stable across independent full traversals, "
        f"got {ours_1} then {ours_2}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
