"""last-modified-round-trips-and-advances-after-a-settled-update."""

from __future__ import annotations

import datetime as dt
import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "last-modified-round-trips-and-advances-after-a-settled-update"
GROUP = "function_config"
SERVICES = ["iam", "lambda"]

_TRUST_POLICY = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "lambda.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
})

_ROLE_NOT_YET_ASSUMABLE = (
    "InvalidParameterValueException",
    "The role defined for the function cannot be assumed by Lambda.",
)


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _zip_of(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", code)
    return buf.getvalue()


def _create_function_once_role_propagates(lam, deadline, **kwargs):
    """CreateFunction, retried only while the just-created role is not yet assumable by Lambda."""
    while True:
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if (err.get("Code"), err.get("Message")) != _ROLE_NOT_YET_ASSUMABLE or (
                time.monotonic() > deadline
            ):
                raise
            time.sleep(3)


def _parse_last_modified(value: str) -> dt.datetime:
    """Parse LastModified's yyyy-MM-ddTHH:mm:ss.SSS+0000 into an aware clock reading, proving the
    exact form by reformatting that reading and matching it back to the input character for
    character.
    """
    assert value.endswith("+0000"), f"LastModified offset is not +0000: {value!r}"
    body = value[: -len("+0000")]
    naive = dt.datetime.strptime(body, "%Y-%m-%dT%H:%M:%S.%f")
    millis = naive.microsecond // 1000
    rebuilt = naive.strftime("%Y-%m-%dT%H:%M:%S.") + f"{millis:03d}" + "+0000"
    assert rebuilt == value, (
        f"LastModified does not round-trip through milliseconds: {value!r} -> {rebuilt!r}"
    )
    return naive.replace(tzinfo=dt.timezone.utc)


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateFunction's LastModified round-trips through an independent GetFunctionConfiguration
    read, and once UpdateFunctionConfiguration settles, GetFunctionConfiguration reports a later
    clock reading in that same millisecond UTC form.
    """
    iam = ctx.client("iam")
    lam = ctx.client("lambda")

    role_name = ctx.unique_name("sim2real-lam-lastmod-role-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_TRUST_POLICY,
    )["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity"))

    function_name = ctx.unique_name("sim2real-lam-lastmod-fn-")
    deadline = time.monotonic() + 90
    create_resp = _create_function_once_role_propagates(
        lam,
        deadline,
        FunctionName=function_name,
        Runtime="python3.12",
        Role=role_arn,
        Handler="index.handler",
        Code={"ZipFile": _zip_of("def handler(event, context):\n    return event\n")},
    )
    ctx.on_cleanup(
        _teardown(lambda: lam.delete_function(FunctionName=function_name), "ResourceNotFoundException")
    )

    created_at = _parse_last_modified(create_resp["LastModified"])

    read_after_create = lam.get_function_configuration(FunctionName=function_name)
    assert read_after_create["LastModified"] == create_resp["LastModified"], (
        "an independent GetFunctionConfiguration read does not match CreateFunction's "
        f"LastModified: create={create_resp['LastModified']!r} "
        f"read={read_after_create['LastModified']!r}"
    )

    active_deadline = time.monotonic() + 90
    active = read_after_create
    while active["State"] == "Pending" and time.monotonic() < active_deadline:
        time.sleep(2)
        active = lam.get_function_configuration(FunctionName=function_name)
    assert active["State"] == "Active", (
        f"the function did not reach Active before the update, State={active['State']!r}"
    )

    lam.update_function_configuration(
        FunctionName=function_name,
        Description="sim2real-lastmod-updated",
    )

    settle_deadline = time.monotonic() + 60
    settled = lam.get_function_configuration(FunctionName=function_name)
    while settled["LastUpdateStatus"] == "InProgress" and time.monotonic() < settle_deadline:
        time.sleep(2)
        settled = lam.get_function_configuration(FunctionName=function_name)

    assert settled["LastUpdateStatus"] == "Successful", (
        f"UpdateFunctionConfiguration settled to {settled['LastUpdateStatus']!r}, not Successful"
    )
    assert settled["Description"] == "sim2real-lastmod-updated", (
        f"the settled configuration does not reflect the update: {settled['Description']!r}"
    )

    settled_at = _parse_last_modified(settled["LastModified"])
    assert settled_at > created_at, (
        "the settled LastModified did not advance past CreateFunction's: "
        f"create={create_resp['LastModified']!r} settled={settled['LastModified']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
