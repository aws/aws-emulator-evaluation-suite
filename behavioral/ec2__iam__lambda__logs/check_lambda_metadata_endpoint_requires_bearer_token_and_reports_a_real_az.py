"""lambda-metadata-endpoint-requires-bearer-token-and-reports-a-real-az."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lambda-metadata-endpoint-requires-bearer-token-and-reports-a-real-az"
GROUP = "metadata-endpoint"
SERVICES = ["ec2", "iam", "lambda", "logs"]

_HANDLER_CODE = '''
import json
import os
import urllib.error
import urllib.request


def lambda_handler(event, context):
    api = os.environ["AWS_LAMBDA_METADATA_API"]
    token = os.environ["AWS_LAMBDA_METADATA_TOKEN"]
    url = "http://{}/2026-01-15/metadata/execution-environment".format(api)

    authed_req = urllib.request.Request(url, headers={"Authorization": "Bearer " + token})
    with urllib.request.urlopen(authed_req, timeout=5) as resp:
        authed_status = resp.status
        authed_content_type = resp.headers.get("Content-Type")
        authed_body = json.loads(resp.read().decode("utf-8"))

    noauth_req = urllib.request.Request(url)
    try:
        with urllib.request.urlopen(noauth_req, timeout=5) as resp2:
            noauth_status = resp2.status
            noauth_body = resp2.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        noauth_status = exc.code
        noauth_body = exc.read().decode("utf-8")

    return {
        "authed_status": authed_status,
        "authed_content_type": authed_content_type,
        "authed_body": authed_body,
        "noauth_status": noauth_status,
        "noauth_body": noauth_body,
    }
'''


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx: Any) -> None:
    """The in-execution-environment Lambda metadata endpoint refuses a GET with no bearer
    token, while the same request carrying it returns the environment's own AvailabilityZoneID,
    one of the region's real AZ ids."""
    ec2 = ctx.client("ec2")
    valid_zone_ids = {
        z["ZoneId"]
        for z in ec2.describe_availability_zones(
            Filters=[{"Name": "region-name", "Values": [ctx.region]}]
        )["AvailabilityZones"]
    }
    assert valid_zone_ids, f"DescribeAvailabilityZones returned no AZ ids for {ctx.region!r}"

    role_arn = _create_basic_role(ctx)
    fn_name = ctx.unique_name("sim2real-xsvc-lmeta-")
    _create_function(ctx, name=fn_name, role_arn=role_arn, handler_source=_HANDLER_CODE)

    lam = ctx.client("lambda")
    resp = lam.invoke(FunctionName=fn_name, InvocationType="RequestResponse", Payload=b"{}")
    assert resp["StatusCode"] == 200, f"expected invoke StatusCode 200, got {resp['StatusCode']}"
    assert "FunctionError" not in resp, f"function raised instead of returning: {resp.get('FunctionError')!r}"
    payload = json.loads(resp["Payload"].read())

    assert payload["authed_status"] == 200, (
        f"expected the bearer-token-authenticated request to return 200, got {payload['authed_status']}"
    )
    assert payload["authed_content_type"] == "application/json", (
        f"expected Content-Type application/json, got {payload['authed_content_type']!r}"
    )
    az_id = payload["authed_body"]["AvailabilityZoneID"]
    assert az_id in valid_zone_ids, (
        f"AvailabilityZoneID {az_id!r} is not one of {sorted(valid_zone_ids)!r} returned by "
        f"DescribeAvailabilityZones for {ctx.region!r}"
    )

    assert payload["noauth_status"] == 401, (
        f"expected a request with no Authorization header to be refused 401, got "
        f"{payload['noauth_status']}: {payload['noauth_body']!r}"
    )
    assert payload["noauth_body"] == _NOAUTH_BODY, (
        f"expected the refused request's body {_NOAUTH_BODY!r}, got {payload['noauth_body']!r}"
    )


# ===== helpers (self-contained) =====

_NOAUTH_BODY = "Unauthorized\n"


_ROLE_NOT_YET = ("InvalidParameterValueException", "The role defined for the function cannot be assumed by Lambda.")


def _zip_from_source(filename: str, source: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, source)
    return buf.getvalue()


def _poll_until(probe, predicate, timeout_s: float = 60.0, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _create_basic_role(ctx: Any) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-xsvc-lmeta-role-")
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"

    def _cleanup() -> None:
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(_cleanup)
    role_arn = resp["Role"]["Arn"]
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    return role_arn


def _create_function(ctx: Any, *, name: str, role_arn: str, handler_source: str, timeout_s: float = 120.0) -> str:
    lam = ctx.client("lambda")
    zip_bytes = _zip_from_source("lambda_function.py", handler_source)
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            resp = lam.create_function(
                FunctionName=name,
                Runtime="python3.13",
                Role=role_arn,
                Handler="lambda_function.lambda_handler",
                Code={"ZipFile": zip_bytes},
                Timeout=30,
                MemorySize=128,
                Tags={"sim2real": "true"},
            )
            break
        except ClientError as exc:
            err = exc.response["Error"]
            if (err["Code"], err["Message"]) != _ROLE_NOT_YET or time.monotonic() > deadline:
                raise
            time.sleep(3)
    ctx.on_cleanup(lambda: _reap_log_group(ctx.client("logs"), f"/aws/lambda/{name}"))
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    cfg = _poll_until(
        lambda: lam.get_function_configuration(FunctionName=name),
        lambda c: c["State"] in ("Active", "Failed"),
        timeout_s=90.0,
        interval_s=2.0,
    )
    if cfg["State"] != "Active":
        raise AssertionError(f"function failed to activate: {cfg.get('StateReason')}")
    return resp["FunctionArn"]


def _reap_log_group(logs, name: str, *, reads: int = 3, interval_s: float = 5.0, budget_s: float = 180.0) -> None:
    """Delete log group ``name`` until ``reads`` consecutive reads find it absent.

    A buffered log line can flush and recreate the group after a single delete, so one
    delete is not a teardown: raises if it is still coming back when ``budget_s`` runs out.
    """
    deadline = time.monotonic() + budget_s
    absent = 0
    while absent < reads:
        groups = logs.describe_log_groups(logGroupNamePrefix=name)["logGroups"]
        if any(g["logGroupName"] == name for g in groups):
            absent = 0
            try:
                logs.delete_log_group(logGroupName=name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        else:
            absent += 1
        if absent < reads:
            if time.monotonic() > deadline:
                raise AssertionError(
                    f"log group {name} still present after {budget_s}s of deletes; {absent} clean reads"
                )
            time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
