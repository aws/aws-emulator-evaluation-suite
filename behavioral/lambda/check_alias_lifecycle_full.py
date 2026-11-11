"""alias-lifecycle-full."""
from __future__ import annotations

import io
import json
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "alias-lifecycle-full"
GROUP = "state-machine"
SERVICES = ["lambda"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Alias create/get/update/delete transitions with removal from ListAliases and 404 on GetAlias after delete."""
    lam = ctx.client("lambda")
    fn = _create_basic_function(ctx)
    version = lam.publish_version(FunctionName=fn["name"])["Version"]
    alias_name = ctx.unique_name("sim2real-alias-")

    created = lam.create_alias(
        FunctionName=fn["name"], Name=alias_name, FunctionVersion=version, Description="v1"
    )
    ctx.on_cleanup(lambda: _delete_alias_ignore(lam, fn["name"], alias_name))
    assert created["FunctionVersion"] == version, (
        f"expected new alias to point at version {version}, got {created['FunctionVersion']!r}"
    )
    assert created["Description"] == "v1", f"expected alias description 'v1', got {created['Description']!r}"

    got = lam.get_alias(FunctionName=fn["name"], Name=alias_name)
    assert got["FunctionVersion"] == version, (
        f"GetAlias returned version {got['FunctionVersion']!r}, expected {version}"
    )
    assert got["AliasArn"] == created["AliasArn"], (
        f"GetAlias AliasArn {got['AliasArn']!r} does not match CreateAlias AliasArn {created['AliasArn']!r}"
    )

    updated = lam.update_alias(FunctionName=fn["name"], Name=alias_name, Description="v2")
    assert updated["Description"] == "v2", f"expected updated description 'v2', got {updated['Description']!r}"
    assert updated["RevisionId"] != created["RevisionId"], "RevisionId must change after a successful UpdateAlias"

    got_after_update = lam.get_alias(FunctionName=fn["name"], Name=alias_name)
    assert got_after_update["Description"] == "v2", (
        f"GetAlias after update returned description {got_after_update['Description']!r}, expected 'v2'"
    )

    names = _list_alias_names(lam, fn["name"])
    assert alias_name in names, "alias missing from ListAliases while it still exists"

    lam.delete_alias(FunctionName=fn["name"], Name=alias_name)

    names_after_delete = _list_alias_names(lam, fn["name"])
    assert alias_name not in names_after_delete, "alias still present in ListAliases after delete"

    code, code_msg = _error(lambda: lam.get_alias(FunctionName=fn["name"], Name=alias_name))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    assert code_msg == f"Cannot find alias arn: arn:aws:lambda:{ctx.region}:{ctx.account}:function:{fn['name']}:{alias_name}", (
        f"expected the exact 'ResourceNotFoundException' message, got {code_msg!r}"
    )

    # A mutation on the dead alias id must also fail, not just the read.
    update_code, update_code_msg = _error(
        lambda: lam.update_alias(FunctionName=fn["name"], Name=alias_name, Description="post-delete")
    )
    assert update_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException from UpdateAlias on a deleted alias, got {update_code}"
    )
    assert update_code_msg == f"Alias not found: arn:aws:lambda:{ctx.region}:{ctx.account}:function:{fn['name']}:{alias_name}", (
        f"expected the exact 'ResourceNotFoundException' message, got {update_code_msg!r}"
    )

    # The identifier is reusable once vacated.
    recreated = lam.create_alias(
        FunctionName=fn["name"], Name=alias_name, FunctionVersion=version, Description="v1 again"
    )
    assert recreated["FunctionVersion"] == version, (
        f"expected recreated alias to point at version {version}, got {recreated['FunctionVersion']!r}"
    )

    got_recreated = lam.get_alias(FunctionName=fn["name"], Name=alias_name)
    assert got_recreated["AliasArn"] == recreated["AliasArn"], (
        f"recreated alias not visible via independent GetAlias read: "
        f"got AliasArn {got_recreated['AliasArn']!r}, expected {recreated['AliasArn']!r}"
    )


def _error(fn):
    """Run *fn*, which AWS must refuse; return the refusal's (code, message)."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded with {result!r}")


def _lambda_zip_bytes() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", "def handler(event, context):\n    return {'ok': True}\n")
    return buf.getvalue()


def _create_exec_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    return role["Role"]["Arn"]


def _create_basic_function(ctx) -> dict:
    lam = ctx.client("lambda")
    role_arn = _create_exec_role(ctx)
    name = ctx.unique_name("sim2real-behav-fn-")
    deadline = time.monotonic() + 90
    resp = None
    while time.monotonic() < deadline:
        try:
            resp = lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="lambda_function.handler",
                Code={"ZipFile": _lambda_zip_bytes()},
                Timeout=10,
                MemorySize=128,
                Publish=False,
                Tags={"sim2real:managed": "true"},
            )
            break
        except Exception as e:
            if "cannot be assumed" in str(e) or "InvalidParameterValueException" in str(e):
                time.sleep(3)
                continue
            raise
    if resp is None:
        raise AssertionError("create_function never succeeded (role propagation timeout)")
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    _wait_function_active(ctx, name)
    return {"name": name, "arn": resp["FunctionArn"], "role_arn": role_arn}


def _wait_function_active(ctx, name: str) -> dict:
    lam = ctx.client("lambda")
    deadline = time.monotonic() + 90
    cfg = None
    while time.monotonic() < deadline:
        cfg = lam.get_function_configuration(FunctionName=name)
        if cfg["State"] == "Active":
            return cfg
        if cfg["State"] == "Failed":
            raise AssertionError(f"function entered Failed state: {cfg.get('StateReason')}")
        time.sleep(2)
    raise AssertionError(f"function did not become Active in time (last={cfg!r})")


def _list_alias_names(lam, function_name: str) -> list:
    marker = None
    names: list = []
    while True:
        kwargs = {"FunctionName": function_name, "MaxItems": 50}
        if marker:
            kwargs["Marker"] = marker
        resp = lam.list_aliases(**kwargs)
        names.extend(a["Name"] for a in resp.get("Aliases", []))
        marker = resp.get("NextMarker")
        if not marker:
            return names


def _delete_alias_ignore(lam, function_name: str, alias_name: str) -> None:
    from botocore.exceptions import ClientError

    try:
        lam.delete_alias(FunctionName=function_name, Name=alias_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
