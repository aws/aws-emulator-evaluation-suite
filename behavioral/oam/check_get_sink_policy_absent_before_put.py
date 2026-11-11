"""get-sink-policy-absent-before-put."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-sink-policy-absent-before-put"
GROUP = "state"
SERVICES = ["oam"]
_NOT_FOUND = "Resource not found."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:oam-sink")
def run(ctx) -> None:
    """GetSinkPolicy is NotFound for a freshly created sink until PutSinkPolicy attaches one."""
    oam = ctx.client("oam")
    account_id = _own_account_id(ctx)

    sink_name = ctx.unique_name("sim2real-oam-sink-")
    sink = _create_sink_retrying(oam, sink_name)
    sink_arn = sink["Arn"]
    ctx.on_cleanup(lambda: _delete_sink_ignore_missing(oam, sink_arn))

    code, code_message = _error(lambda: oam.get_sink_policy(SinkIdentifier=sink_arn))
    assert code == "ResourceNotFoundException", (
        f"want=ResourceNotFoundException have={code!r}"
    )
    assert code_message == _NOT_FOUND, f"got message {code_message!r}"

    policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Action": ["oam:CreateLink", "oam:UpdateLink"],
                    "Effect": "Allow",
                    "Resource": "*",
                    "Principal": {"AWS": [account_id]},
                }
            ],
        }
    )
    oam.put_sink_policy(SinkIdentifier=sink_arn, Policy=policy)

    got = oam.get_sink_policy(SinkIdentifier=sink_arn)
    assert got["Policy"], f"want=non-empty Policy have={got.get('Policy')!r}"
    want = json.loads(policy)
    have = json.loads(got["Policy"])
    want_norm = _strip_sids(want)
    have_norm = _strip_sids(have)
    want_stmt = want["Statement"][0]
    have_stmt = have.get("Statement", [{}])[0]
    diffs = {
        k: (want_stmt.get(k), have_stmt.get(k))
        for k in set(want_stmt) | set(have_stmt)
        if want_stmt.get(k) != have_stmt.get(k)
    }
    assert have_norm == want_norm, f"stmt_value_diffs={diffs!r}"


def _error(fn):
    """Call fn(), which must fail; return its botocore error (code, message). An unexpected
    SUCCESS raises, so a target that accepts what AWS refuses is never read as a mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _strip_sids(policy_doc):
    doc = json.loads(json.dumps(policy_doc))
    for stmt in doc.get("Statement", []):
        stmt.pop("Sid", None)
        principal = stmt.get("Principal")
        if isinstance(principal, dict) and "AWS" in principal:
            aws = principal["AWS"]
            aws_list = aws if isinstance(aws, list) else [aws]
            # AWS normalizes a bare 12-digit account id into its root-user ARN form
            # ("arn:aws:iam::<account>:root"); compare on the extracted account id only.
            normalized = sorted(
                v.split(":")[4] if v.startswith("arn:aws:iam::") else v for v in aws_list
            )
            stmt["Principal"] = {"AWS": normalized}
    return doc


def _own_account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


def _create_sink_retrying(oam, name, timeout_s=90.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return oam.create_sink(Name=name, Tags={"env": "sim2real"})
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ServiceQuotaExceededException":
                last_exc = exc
                time.sleep(interval_s)
                continue
            raise
    raise last_exc


def _delete_sink_ignore_missing(oam, arn):
    try:
        oam.delete_sink(Identifier=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
