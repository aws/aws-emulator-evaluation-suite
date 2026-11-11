"""put-resource-policy-concurrent-writes-settle-on-one-policy."""
from __future__ import annotations

import json
import threading
import time

from behavioral_harness import tags


CHECK = "put-resource-policy-concurrent-writes-settle-on-one-policy"
GROUP = "concurrency"
SERVICES = ["bedrock"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two concurrent PutResourcePolicy writes on one guardrail both succeed and settle on exactly
    one submitted policy, not a stale, dropped, or merged one.

    Reference: https://docs.aws.amazon.com/bedrock/latest/APIReference/API_PutResourcePolicy.html
    """
    bedrock = ctx.client("bedrock")

    guardrail = bedrock.create_guardrail(
        name=ctx.unique_name("sim2real-bedrock-gr-"),
        blockedInputMessaging="Sorry, I can't help with that input.",
        blockedOutputsMessaging="Sorry, I can't help with that output.",
        wordPolicyConfig={"wordsConfig": [{"text": "sim2realblockedword"}]},
        tags=[{"key": "sim2real", "value": "put-resource-policy-concurrent-writes"}],
    )
    guardrail_arn = guardrail["guardrailArn"]
    ctx.on_cleanup(lambda: _safe_delete_guardrail(bedrock, guardrail_arn))
    _wait_for_guardrail_ready(bedrock, guardrail_arn, timeout_s=60)

    account_id = guardrail_arn.split(":")[4]
    variant_a = "both_actions"
    variant_b = "apply_only"
    expected_statements = {
        variant: _normalize_statement(
            json.loads(_policy_document(guardrail_arn, variant, account_id))["Statement"][0]
        )
        for variant in (variant_a, variant_b)
    }

    results: dict[str, object] = {}

    def _put(key: str, variant: str) -> None:
        policy_doc = _policy_document(guardrail_arn, variant, account_id)
        try:
            bedrock.put_resource_policy(
                resourceArn=guardrail_arn,
                resourcePolicy=policy_doc,
            )
            results[key] = "ok"
        except Exception as exc:  # noqa: BLE001
            results[key] = (exc, policy_doc)

    t1 = threading.Thread(target=_put, args=("a", variant_a))
    t2 = threading.Thread(target=_put, args=("b", variant_b))
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    assert results["a"] == "ok", f"PutResourcePolicy A unexpectedly failed: {results['a']}"
    assert results["b"] == "ok", f"PutResourcePolicy B unexpectedly failed: {results['b']}"

    final_variant = _wait_for_settled_variant(bedrock, guardrail_arn, expected_statements, timeout_s=60)
    assert final_variant in (variant_a, variant_b), (
        f"resource policy settled on neither submitted document exactly: {final_variant!r}"
    )


def _policy_document(guardrail_arn: str, variant: str, account_id: str) -> str:
    actions = (
        ["bedrock:ApplyGuardrail", "bedrock:GetGuardrail"]
        if variant == "both_actions"
        else ["bedrock:ApplyGuardrail"]
    )
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": f"sim2real-{variant}",
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                    "Action": actions,
                    "Resource": guardrail_arn,
                }
            ],
        }
    )



def _safe_delete_guardrail(bedrock, guardrail_arn: str) -> None:
    """Delete the guardrail; an already-deleted guardrail needs nothing."""
    from botocore.exceptions import ClientError

    try:
        bedrock.delete_guardrail(guardrailIdentifier=guardrail_arn)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _wait_for_guardrail_ready(bedrock, guardrail_arn: str, timeout_s: float) -> None:
    deadline = time.monotonic() + timeout_s
    status = ""
    while time.monotonic() < deadline:
        status = bedrock.get_guardrail(guardrailIdentifier=guardrail_arn)["status"]
        if status == "READY":
            return
        time.sleep(2)
    raise AssertionError(f"guardrail did not reach READY within the timeout (last status: {status!r})")



def _normalize_statement(stmt: dict) -> dict:
    """Sort Action into a list: GetResourcePolicy echoes a singleton Action array as a bare string,
    which must not be mistaken for a corrupted or merged statement.
    """
    normalized = dict(stmt)
    actions = normalized.get("Action", [])
    if isinstance(actions, str):
        actions = [actions]
    normalized["Action"] = sorted(actions)
    return normalized


def _wait_for_settled_variant(
    bedrock, guardrail_arn: str, expected_statements: dict[str, dict], timeout_s: float
) -> str:
    deadline = time.monotonic() + timeout_s
    last_statements: list = []
    while time.monotonic() < deadline:
        raw_policy = bedrock.get_resource_policy(resourceArn=guardrail_arn)["resourcePolicy"]
        statements = json.loads(raw_policy).get("Statement", [])
        last_statements = statements
        if len(statements) == 1:
            observed = _normalize_statement(statements[0])
            for variant, expected in expected_statements.items():
                if observed == expected:
                    return variant
        time.sleep(2)
    raise AssertionError(
        "resource policy never settled on either submitted document within "
        f"{timeout_s}s (last observed statements: {last_statements!r})"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

