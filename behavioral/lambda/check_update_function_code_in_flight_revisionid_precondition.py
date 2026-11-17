"""update-function-code-in-flight-revisionid-precondition."""

from __future__ import annotations

import io
import json
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-function-code-in-flight-revisionid-precondition"
GROUP = "code_updates"
SERVICES = ["lambda", "iam"]

_ROLE_NOT_READY = "The role defined for the function cannot be assumed by Lambda."
_TRUST = {
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "lambda.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
}


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises; only ``not_found`` means gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _make_zip(code: str, filename: str = "index.py") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, textwrap.dedent(code))
    return buf.getvalue()


def _make_role(ctx, iam) -> str:
    """This check's own execution role; the handler never runs so no log group is created."""
    name = ctx.unique_name("sim2real-behav-l6-")
    role = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=json.dumps(_TRUST),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    return role["Role"]["Arn"]


def _create_function(ctx, lam, **kwargs) -> dict:
    """CreateFunction, retried only while the just-created role is not yet assumable."""
    name = kwargs["FunctionName"]
    deadline = time.monotonic() + 90.0
    while True:
        try:
            created = lam.create_function(**kwargs)
            break
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] != "InvalidParameterValueException" or err.get("Message") != _ROLE_NOT_READY:
                raise
            if time.monotonic() > deadline:
                raise AssertionError(f"CreateFunction kept failing on role propagation: {err!r}")
            time.sleep(3)
    ctx.on_cleanup(_teardown(lambda: lam.delete_function(FunctionName=name), "ResourceNotFoundException"))
    _wait_ready(lam, name)
    return created


def _wait_ready(lam, name: str, timeout_s: float = 120.0) -> dict:
    """Poll until the function is Active with its last update Successful; returns that read."""
    deadline = time.monotonic() + timeout_s
    while True:
        cfg = lam.get_function_configuration(FunctionName=name)
        if cfg.get("State") == "Failed" or cfg.get("LastUpdateStatus") == "Failed":
            raise AssertionError(
                f"{name} failed: {cfg.get('StateReason')!r} {cfg.get('LastUpdateStatusReason')!r}"
            )
        if cfg.get("State") == "Active" and cfg.get("LastUpdateStatus") in (None, "Successful"):
            return cfg
        if time.monotonic() > deadline:
            raise AssertionError(f"{name} not ready within {timeout_s}s: {cfg!r}")
        time.sleep(1.0)


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError ``fn`` raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateFunctionConfiguration with the RevisionId that UpdateFunctionCode just returned is
    refused once the deployment settles onto a further RevisionId, and the same call carrying
    the settled RevisionId succeeds.
    """
    lam = ctx.client("lambda")
    role = _make_role(ctx, ctx.client("iam"))
    fn = ctx.unique_name("sim2real-behav-l6-coderev-")
    _create_function(
        ctx, lam, FunctionName=fn, Runtime="python3.12", Handler="index.handler", Role=role,
        Code={"ZipFile": _make_zip("def handler(event, context): return {'v': 1}")},
        Timeout=10, Tags={"sim2real": CHECK},
    )

    before = lam.get_function_configuration(FunctionName=fn)["RevisionId"]
    in_flight = lam.update_function_code(
        FunctionName=fn, ZipFile=_make_zip("def handler(event, context): return {'v': 2}")
    )["RevisionId"]
    assert in_flight != before, (
        f"expected UpdateFunctionCode to mint a RevisionId distinct from the pre-update one, "
        f"before={before!r} response={in_flight!r}"
    )

    settled_cfg = _wait_ready(lam, fn)
    settled = settled_cfg["RevisionId"]
    assert settled not in (before, in_flight), (
        f"expected the settled RevisionId to differ from both the pre-update and the in-flight "
        f"response one, before={before!r} response={in_flight!r} settled={settled!r}"
    )
    again = lam.get_function_configuration(FunctionName=fn)["RevisionId"]
    assert again == settled, (
        f"expected a second independent read to agree on the settled RevisionId, "
        f"first={settled!r} second={again!r}"
    )
    description_at_settle = settled_cfg.get("Description")

    code, message = _error(
        lambda: lam.update_function_configuration(
            FunctionName=fn, Description="sim2real-rejected-probe", RevisionId=in_flight
        )
    )
    assert code == "PreconditionFailedException", (
        f"expected the in-flight RevisionId to be refused with PreconditionFailedException, got {code!r}"
    )
    expected_message = (
        "The Revision Id provided does not match the latest Revision Id. "
        "Call the GetFunction/GetAlias API to retrieve the latest Revision Id"
    )
    assert message == expected_message, (
        f"expected the exact PreconditionFailedException message {expected_message!r}, got {message!r}"
    )

    after_refusal = lam.get_function_configuration(FunctionName=fn)
    assert after_refusal["RevisionId"] == settled, (
        f"a refused UpdateFunctionConfiguration must not advance RevisionId, "
        f"expected {settled!r}, got {after_refusal['RevisionId']!r}"
    )
    assert after_refusal.get("Description") == description_at_settle, (
        f"a refused UpdateFunctionConfiguration must not apply, "
        f"expected Description={description_at_settle!r}, got {after_refusal.get('Description')!r}"
    )

    lam.update_function_configuration(
        FunctionName=fn, Description="sim2real-accepted-probe", RevisionId=settled
    )
    confirmed = _wait_ready(lam, fn)
    assert confirmed["Description"] == "sim2real-accepted-probe", (
        f"the identical call carrying the settled RevisionId must succeed, got {confirmed!r}"
    )
    assert confirmed["RevisionId"] != settled, (
        "a successful UpdateFunctionConfiguration must advance RevisionId again"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
