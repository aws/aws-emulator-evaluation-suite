"""put-sink-policy-round-trip."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-sink-policy-round-trip"
GROUP = "state"
SERVICES = ["oam"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:oam-sink")
def run(ctx) -> None:
    """PutSinkPolicy persists the exact policy document, and a second call fully replaces it."""
    oam = ctx.client("oam")
    account_id = _own_account_id(ctx)

    sink_name = ctx.unique_name("sim2real-oam-sink-")
    sink = _create_sink_retrying(oam, sink_name, tags={"sim2real": CHECK})
    sink_arn = sink["Arn"]
    ctx.on_cleanup(lambda: _delete_sink_ignore_missing(oam, sink_arn))

    policy1 = json.dumps(
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
    resp1 = oam.put_sink_policy(SinkIdentifier=sink_arn, Policy=policy1)
    assert resp1["SinkArn"] == sink_arn, f"want SinkArn={sink_arn!r} have={resp1['SinkArn']!r}"
    got1 = oam.get_sink_policy(SinkIdentifier=sink_arn)
    want1 = _strip_sids(json.loads(policy1))
    have1 = _strip_sids(json.loads(got1["Policy"]))
    assert have1 == want1, f"want={want1!r} have={have1!r}"

    policy2 = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Action": ["oam:CreateLink", "oam:UpdateLink"],
                    "Effect": "Allow",
                    "Resource": "*",
                    "Principal": {"AWS": [account_id]},
                    "Condition": {
                        "ForAllValues:StringEquals": {
                            "oam:ResourceTypes": ["AWS::CloudWatch::Metric"]
                        }
                    },
                }
            ],
        }
    )
    oam.put_sink_policy(SinkIdentifier=sink_arn, Policy=policy2)
    got2 = oam.get_sink_policy(SinkIdentifier=sink_arn)
    want2 = _strip_sids(json.loads(policy2))
    have2 = _strip_sids(json.loads(got2["Policy"]))
    want2_stmt = want2["Statement"][0]
    have2_stmt = have2.get("Statement", [{}])[0]
    msg = repr(have2_stmt.get("Condition"))[:80] + "||" + repr(want2_stmt.get("Condition"))[:80]
    assert have2 == want2, msg
    replaced = _strip_sids(json.loads(got2["Policy"]))
    original = _strip_sids(json.loads(policy1))
    assert replaced != original, f"policy2 read-back still matches policy1: {replaced!r}"


def _own_account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


def _strip_sids(policy_doc):
    doc = json.loads(json.dumps(policy_doc))
    for stmt in doc.get("Statement", []):
        stmt.pop("Sid", None)
        principal = stmt.get("Principal")
        if isinstance(principal, dict) and "AWS" in principal:
            aws = principal["AWS"]
            aws_list = aws if isinstance(aws, list) else [aws]
            normalized = sorted(
                v.split(":")[4] if v.startswith("arn:aws:iam::") else v for v in aws_list
            )
            stmt["Principal"] = {"AWS": normalized}
        condition = stmt.get("Condition")
        if isinstance(condition, dict):
            # AWS collapses a single-element condition-value list to a bare scalar.
            for op_values in condition.values():
                if isinstance(op_values, dict):
                    for key, val in list(op_values.items()):
                        if isinstance(val, list) and len(val) == 1:
                            op_values[key] = val[0]
    return doc


def _create_sink_retrying(oam, name, timeout_s=90.0, interval_s=3.0, tags=None):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return oam.create_sink(Name=name, Tags=tags or {})
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
