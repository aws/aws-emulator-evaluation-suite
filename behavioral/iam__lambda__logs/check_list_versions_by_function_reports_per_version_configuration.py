"""list-versions-by-function-reports-per-version-configuration."""

from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-versions-by-function-reports-per-version-configuration"
GROUP = "versions_aliases"
SERVICES = ["iam", "lambda", "logs"]

_BASIC_EXEC = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
_ROLE_NOT_READY = "The role defined for the function cannot be assumed by Lambda."


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _zip(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", code)
    return buf.getvalue()


def _create_role(ctx):
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-lvbfrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
                           Tags=[{"Key": "sim2real", "Value": CHECK}])["Role"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    iam.attach_role_policy(RoleName=name, PolicyArn=_BASIC_EXEC)
    ctx.on_cleanup(_teardown(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=_BASIC_EXEC), "NoSuchEntity"))
    return role["Arn"]


def _create_function(lam, **kwargs):
    deadline = time.monotonic() + 90.0
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


def _wait_active(lam, fn, timeout_s=90.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = lam.get_function_configuration(FunctionName=fn)
        if last["State"] == "Failed":
            raise AssertionError(f"function {fn} entered Failed: {last.get('StateReason')}")
        if last["State"] == "Active":
            return
        time.sleep(1.5)
    raise AssertionError(f"{fn} did not become Active within {timeout_s}s; last={last!r}")


def _wait_updated(lam, fn, timeout_s=90.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = lam.get_function_configuration(FunctionName=fn)
        status = last.get("LastUpdateStatus")
        if status == "Failed":
            raise AssertionError(f"function {fn} update failed: {last.get('LastUpdateStatusReason')}")
        if status == "Successful":
            return
        time.sleep(1.5)
    raise AssertionError(f"{fn} update did not settle within {timeout_s}s; last={last!r}")


def _delete_log_group(ctx, name: str) -> None:
    try:
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{name}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListVersionsByFunction reports each published version's own Timeout, MemorySize, CodeSize,
    CodeSha256 and LastModified rather than the function's current configuration.
    """
    lam = ctx.client("lambda")
    role_arn = _create_role(ctx)
    fn = ctx.unique_name("sim2real-behav-lvbf-")

    ctx.on_cleanup(lambda: _delete_log_group(ctx, fn))
    _create_function(
        lam,
        FunctionName=fn,
        Runtime="python3.12",
        Handler="index.handler",
        Role=role_arn,
        Code={"ZipFile": _zip("def handler(e, c):\n    return {'v': 1}\n")},
        MemorySize=128,
        Timeout=10,
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(_teardown(lambda: lam.delete_function(FunctionName=fn), "ResourceNotFoundException"))
    _wait_active(lam, fn)

    v1 = lam.publish_version(FunctionName=fn, Description="v1")
    assert v1["Version"] == "1", f"first published version should be '1', got {v1['Version']!r}"

    lam.update_function_code(FunctionName=fn, ZipFile=_zip("def handler(e, c):\n    return {'v': 2}\n"))
    _wait_updated(lam, fn)
    lam.update_function_configuration(FunctionName=fn, Timeout=20, MemorySize=256)
    _wait_updated(lam, fn)

    v2 = lam.publish_version(FunctionName=fn, Description="v2")
    assert v2["Version"] == "2", f"second published version should be '2', got {v2['Version']!r}"

    assert v1["CodeSha256"] != v2["CodeSha256"], (
        f"changed code must change CodeSha256: v1={v1['CodeSha256']!r}, v2={v2['CodeSha256']!r}"
    )
    assert (v1["Timeout"], v1["MemorySize"]) != (v2["Timeout"], v2["MemorySize"]), (
        f"changed configuration must change Timeout/MemorySize: v1={(v1['Timeout'], v1['MemorySize'])!r}, "
        f"v2={(v2['Timeout'], v2['MemorySize'])!r}"
    )

    by_version = {}
    marker = None
    while True:
        kwargs = {"FunctionName": fn}
        if marker:
            kwargs["Marker"] = marker
        page = lam.list_versions_by_function(**kwargs)
        for entry in page["Versions"]:
            by_version[entry["Version"]] = entry
        marker = page.get("NextMarker")
        if not marker:
            break

    assert set(by_version) == {"$LATEST", "1", "2"}, (
        f"ListVersionsByFunction returned versions {sorted(by_version)}, expected $LATEST, 1 and 2"
    )

    for version, published in (("1", v1), ("2", v2)):
        entry = by_version[version]
        got = (entry["Timeout"], entry["MemorySize"], entry["CodeSize"], entry["CodeSha256"], entry["LastModified"])
        want = (published["Timeout"], published["MemorySize"], published["CodeSize"],
                published["CodeSha256"], published["LastModified"])
        assert got == want, (
            f"ListVersionsByFunction entry for version {version!r} reported "
            f"(Timeout, MemorySize, CodeSize, CodeSha256, LastModified)={got!r}, expected the values "
            f"PublishVersion itself returned {want!r}"
        )

    latest = by_version["$LATEST"]
    assert (latest["Timeout"], latest["MemorySize"], latest["CodeSha256"]) == (
        v2["Timeout"], v2["MemorySize"], v2["CodeSha256"]
    ), (
        f"$LATEST should carry the current (post-v2) configuration "
        f"{(v2['Timeout'], v2['MemorySize'], v2['CodeSha256'])!r}, got "
        f"{(latest['Timeout'], latest['MemorySize'], latest['CodeSha256'])!r}"
    )

    one, two = by_version["1"], by_version["2"]
    assert (one["Timeout"], one["MemorySize"], one["CodeSize"], one["CodeSha256"]) != (
        two["Timeout"], two["MemorySize"], two["CodeSize"], two["CodeSha256"]
    ), "versions 1 and 2 must carry distinct configuration, not the function's shared current state"
    assert one["LastModified"] < two["LastModified"], (
        f"version 1 was published before version 2, so its LastModified {one['LastModified']!r} "
        f"must sort before version 2's {two['LastModified']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
