"""put-sink-policy-wildcard-principal-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "put-sink-policy-wildcard-principal-rejected"
GROUP = "overly-permissive"
SERVICES = ["oam"]
_NOT_FOUND = "Resource not found."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:oam-sink")
def run(ctx) -> None:
    """PutSinkPolicy rejects a statement missing the required Principal element (a resource
    policy must say who it grants access to); a policy scoped to the correct actions is accepted
    -- even with an unconditioned wildcard Principal, which real AWS does NOT reject on its own."""
    oam = ctx.client("oam")
    _own_account_id(ctx)

    sink_name = ctx.unique_name("sim2real-oam-sink-")
    sink = _create_sink_retrying(oam, sink_name)
    sink_arn = sink["Arn"]
    ctx.on_cleanup(lambda: _delete_sink_ignore_missing(oam, sink_arn))

    # a policy statement missing the required Principal element (a resource policy must specify
    # who it grants access to) is rejected.
    no_principal_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Action": ["oam:CreateLink", "oam:UpdateLink"],
                    "Effect": "Allow",
                    "Resource": "*",
                }
            ],
        }
    )
    code, code_message = _error(
        lambda: oam.put_sink_policy(SinkIdentifier=sink_arn, Policy=no_principal_policy)
    )
    assert code == "InvalidParameterException", f"got {code!r}"
    assert code_message == "Policy validation failed", f"got message {code_message!r}"

    # effect absent: no policy was ever attached.
    absent_code, absent_code_message = _error(lambda: oam.get_sink_policy(SinkIdentifier=sink_arn))
    assert absent_code == "ResourceNotFoundException", f"got {absent_code!r}"
    assert absent_code_message == _NOT_FOUND, f"got message {absent_code_message!r}"

    # positive control: a policy scoped to the correct actions is accepted even with an
    # unconditioned wildcard Principal; AWS does not reject wildcard principals on their own.
    wildcard_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Action": ["oam:CreateLink", "oam:UpdateLink"],
                    "Effect": "Allow",
                    "Resource": "*",
                    "Principal": "*",
                }
            ],
        }
    )
    oam.put_sink_policy(SinkIdentifier=sink_arn, Policy=wildcard_policy)
    got = oam.get_sink_policy(SinkIdentifier=sink_arn)
    assert _strip_sids(json.loads(got["Policy"])) == _strip_sids(json.loads(wildcard_policy))


def _error(fn):
    """Call fn(), which must fail; return its botocore error (code, message). An unexpected
    SUCCESS raises, so a target that accepts what AWS refuses is never read as a mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _own_account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


def _strip_sids(policy_doc):
    doc = json.loads(json.dumps(policy_doc))
    for stmt in doc.get("Statement", []):
        stmt.pop("Sid", None)
    return doc


def _create_sink_retrying(oam, name, timeout_s=90.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return oam.create_sink(Name=name)
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
