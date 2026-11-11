"""assume-role-session-name-empty-vs-absent-distinction."""
from __future__ import annotations

import json
import re
import time
from urllib.parse import quote

import requests
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "assume-role-session-name-empty-vs-absent-distinction"
GROUP = "representation"
SERVICES = ["sts"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "concern:representation", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """AssumeRole rejects a RoleSessionName absent from the wire and one sent empty with ValidationError
    and distinct exact messages: "Member must not be null" versus the minimum-length violation. The
    absent case is a hand-signed request, as the SDK refuses to omit a required member."""
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    role_name = ctx.unique_name("sim2real-behav-sessname-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-behav"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    # Positive control: with a valid, present session name the same call succeeds once
    # trust has propagated -- proves the role/permissions are fine and isolates the
    # cases below to RoleSessionName wire-representation handling specifically.
    _wait_for_assume_role(sts, RoleArn=role_arn, RoleSessionName="control-session")

    code_absent, message_absent = _raw_assume_role_error(sts, ctx.region, {"RoleArn": role_arn})
    assert code_absent == "ValidationError", (code_absent, message_absent)

    code_empty, message_empty = _raw_assume_role_error(
        sts, ctx.region, {"RoleArn": role_arn, "RoleSessionName": ""}
    )
    assert code_empty == "ValidationError", (code_empty, message_empty)

    # Both land on the same top-level error CODE (ValidationError is the shared query-
    # protocol validation-failure code for AssumeRole), but the wire-absent case and the
    # wire-present-but-empty case must produce DISTINCT messages -- one about a missing/
    # null required member, the other about violating RoleSessionName's minimum-length
    # constraint. An emulator that can't even tell these two malformed requests apart
    # (identical message, or the wrong one) is not modeling the distinction faithfully.
    assert message_absent == (
        "1 validation error detected: Value null at 'roleSessionName' failed to satisfy "
        "constraint: Member must not be null"
    ), message_absent
    assert message_empty == (
        "1 validation error detected: Value '' at 'roleSessionName' failed to satisfy "
        "constraint: Member must have length greater than or equal to 2"
    ), message_empty


def _raw_assume_role_error(sts_client, region: str, extra_params: dict) -> tuple[str | None, str]:
    """POST a hand-signed AssumeRole query-protocol request, bypassing botocore's
    client-side required-parameter enforcement, and pull the <Code>/<Message> out of the
    raw error XML. Uses the SAME endpoint/credentials the check's boto3 client is already
    wired to, so it works unmodified against real AWS or an emulator target."""
    endpoint = sts_client.meta.endpoint_url.rstrip("/") + "/"
    creds = sts_client._request_signer._credentials
    params = {"Action": "AssumeRole", "Version": "2011-06-15", **extra_params}
    body = "&".join(f"{quote(k, safe='')}={quote(str(v), safe='')}" for k, v in params.items())
    req = AWSRequest(
        method="POST",
        url=endpoint,
        data=body.encode("utf-8"),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    SigV4Auth(creds, "sts", region).add_auth(req)
    resp = requests.post(
        endpoint, data=body.encode("utf-8"), headers=dict(req.headers), timeout=20
    )
    code_match = re.search(r"<Code>([^<]+)</Code>", resp.text)
    message_match = re.search(r"<Message>([^<]*)</Message>", resp.text)
    code = code_match.group(1) if code_match else f"HTTP{resp.status_code}"
    message = message_match.group(1) if message_match else resp.text[:300]
    return code, message


def _wait_for_assume_role(sts_client, timeout_s: float = 30.0, interval_s: float = 2.0, **kwargs):
    deadline = time.monotonic() + timeout_s
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return sts_client.assume_role(**kwargs)["Credentials"]
        except ClientError as err:
            if err.response["Error"]["Code"] != "AccessDenied":
                raise
            last_err = err
            time.sleep(interval_s)
    raise AssertionError(f"assume_role never became permitted within {timeout_s}s: {last_err}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
