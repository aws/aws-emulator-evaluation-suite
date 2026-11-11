"""resource-policy-json-round-trip-byte-equal."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "resource-policy-json-round-trip-byte-equal"
GROUP = "server-side"
SERVICES = ["bedrock"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A resource policy sent to PutResourcePolicy with non-canonical JSON whitespace comes back from
    GetResourcePolicy as the minified serialization of the same document, byte for byte, and parses
    back equal to it: Bedrock normalizes formatting."""
    bedrock = ctx.client("bedrock")
    guardrail = _create_guardrail(ctx, bedrock)
    # The owning account comes from the guardrail's own ARN: the policy's Principal must
    # name the account that owns the guardrail for the "share within your own account"
    # pattern to apply.
    owner_account = guardrail["arn"].split(":")[4]

    # Bedrock guardrail resource policies only accept a narrow, specific set
    # of statement shapes (see "Using resource-based policies for guardrails"
    # in the Bedrock user guide). Try the documented supported patterns in
    # order and use whichever the service actually accepts.
    candidates: list[dict[str, Any]] = [
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{owner_account}:root"},
                    "Action": ["bedrock:ApplyGuardrail", "bedrock:GetGuardrail"],
                    "Resource": guardrail["arn"],
                }
            ],
        },
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": ["bedrock:GetGuardrail", "bedrock:ApplyGuardrail"],
                    "Resource": guardrail["arn"],
                    "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-example000000"}},
                }
            ],
        },
    ]

    accepted_doc: dict[str, Any] | None = None
    last_message = ""
    for policy_doc in candidates:
        # Deliberately non-canonical whitespace (spaces after ':'/',', as
        # json.dumps' default separators produce) -- allowed by the
        # resourcePolicy pattern (space through 0xFF), unlike literal newlines.
        policy_json = json.dumps(policy_doc, sort_keys=False)
        try:
            bedrock.put_resource_policy(resourceArn=guardrail["arn"], resourcePolicy=policy_json)
        except Exception as exc:  # noqa: BLE001 - try next candidate / surface the last message
            from botocore.exceptions import ClientError

            if isinstance(exc, ClientError) and exc.response["Error"]["Code"] == "ValidationException":
                last_message = exc.response["Error"].get("Message", "")
                continue
            raise
        accepted_doc = policy_doc
        break

    if accepted_doc is None:
        raise AssertionError(
            "PutResourcePolicy rejected every documented supported policy-statement "
            f"shape for a guardrail resource policy; last server message: {last_message!r}. "
            "This suggests the actually-enforced supported format is narrower than "
            "documented in this account -- cannot exercise the round trip."
        )

    canonical_json = json.dumps(accepted_doc, separators=(",", ":"), sort_keys=False)
    returned = bedrock.get_resource_policy(resourceArn=guardrail["arn"])["resourcePolicy"]

    # Bedrock canonicalizes the stored policy to minified JSON -- it is not
    # byte-identical to what was sent (which had extra whitespace), but it
    # must be identical to the canonical (no-whitespace) serialization of the
    # exact same document, and must parse back to the same structure.
    assert returned == canonical_json, _diff("resourcePolicy", canonical_json, returned)
    assert json.loads(returned) == accepted_doc, "returned policy is not semantically equal to what was sent"


def _diff(field: str, sent: str, got: str) -> str:
    i = next((i for i, (a, b) in enumerate(zip(sent, got)) if a != b), min(len(sent), len(got)))
    return f"{field}[{i}]: sent={sent[i:i+12]!r} got={got[i:i+12]!r} (lens {len(sent)}/{len(got)})"


def _create_guardrail(ctx, bedrock: Any) -> dict[str, str]:
    name = ctx.unique_name("sim2real-bedrock-gr-")
    resp = bedrock.create_guardrail(
        name=name,
        blockedInputMessaging="Blocked by guardrail policy.",
        blockedOutputsMessaging="Blocked by guardrail policy.",
        contentPolicyConfig={
            "filtersConfig": [
                {"type": "SEXUAL", "inputStrength": "HIGH", "outputStrength": "HIGH"}
            ]
        },
        tags=[{"key": "sim2real", "value": "resource-policy-json-round-trip-byte-equal"}],
    )
    guardrail_id = resp["guardrailId"]
    guardrail_arn = resp["guardrailArn"]
    ctx.on_cleanup(lambda: bedrock.delete_guardrail(guardrailIdentifier=guardrail_id))
    _wait_guardrail_status(bedrock, guardrail_id, {"READY"})
    return {"id": guardrail_id, "arn": guardrail_arn}


def _wait_guardrail_status(
    bedrock: Any,
    guardrail_id: str,
    target_statuses: set[str],
    timeout_s: float = 120.0,
    interval_s: float = 3.0,
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        resp = bedrock.get_guardrail(guardrailIdentifier=guardrail_id)
        last_status = resp["status"]
        if last_status in target_statuses:
            return resp
        time.sleep(interval_s)
    raise AssertionError(
        f"guardrail {guardrail_id} did not reach {target_statuses}, last status {last_status}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
