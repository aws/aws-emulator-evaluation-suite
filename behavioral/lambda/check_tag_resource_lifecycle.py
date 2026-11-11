"""tag-resource-lifecycle."""
from __future__ import annotations

import io
import json
import time
import zipfile

from behavioral_harness import tags

CHECK = "tag-resource-lifecycle"
GROUP = "state-machine"
SERVICES = ["lambda"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Tags applied via TagResource are visible via ListTags and fully removed via UntagResource."""
    lam = ctx.client("lambda")
    fn = _create_basic_function(ctx)

    lam.tag_resource(Resource=fn["arn"], Tags={"sim2real-k1": "v1", "sim2real-k2": "v2"})

    tags = lam.list_tags(Resource=fn["arn"])["Tags"]
    assert tags.get("sim2real-k1") == "v1", f"expected sim2real-k1=v1, got {tags.get('sim2real-k1')!r}"
    assert tags.get("sim2real-k2") == "v2", f"expected sim2real-k2=v2, got {tags.get('sim2real-k2')!r}"

    lam.untag_resource(Resource=fn["arn"], TagKeys=["sim2real-k1"])
    tags_after_partial = lam.list_tags(Resource=fn["arn"])["Tags"]
    assert "sim2real-k1" not in tags_after_partial, "untagged key still present"
    assert tags_after_partial.get("sim2real-k2") == "v2", "unrelated tag was removed"

    lam.untag_resource(Resource=fn["arn"], TagKeys=["sim2real-k2"])
    tags_after_full = lam.list_tags(Resource=fn["arn"])["Tags"]
    assert "sim2real-k1" not in tags_after_full, f"sim2real-k1 still present after untag: {tags_after_full}"
    assert "sim2real-k2" not in tags_after_full, f"sim2real-k2 still present after untag: {tags_after_full}"


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
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
