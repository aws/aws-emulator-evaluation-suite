"""put-resource-policy-malformed-policy-document-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-resource-policy-malformed-policy-document-rejected"
GROUP = "overly-permissive"
SERVICES = ["bedrock"]

_NONCONFORMING_MESSAGE = (
    "The provided policy document does not conform to the supported policy formats. For more "
    "information about valid policy document formats, check out the Amazon Bedrock Guardrails "
    "documentation"
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutResourcePolicy rejects a malformed policy document with ValidationException.

    Nothing is stored by the rejected call; a valid policy is accepted and round-trips exactly.
    """
    bedrock = ctx.client("bedrock")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    guardrail_name = ctx.unique_name("sim2real-rp-gr-")
    created = bedrock.create_guardrail(
        name=guardrail_name,
        blockedInputMessaging="Input blocked by test guardrail.",
        blockedOutputsMessaging="Output blocked by test guardrail.",
        wordPolicyConfig={"wordsConfig": [{"text": ctx.unique_name("bannedword").replace("-", "")}]},
        tags=[{"key": "sim2real", "value": "put-resource-policy-malformed-policy-document-rejected"}],
    )
    guardrail_id = created["guardrailId"]
    guardrail_arn = created["guardrailArn"]

    def _cleanup_guardrail() -> None:
        try:
            bedrock.delete_resource_policy(resourceArn=guardrail_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        bedrock.delete_guardrail(guardrailIdentifier=guardrail_id)

    ctx.on_cleanup(_cleanup_guardrail)

    # The guardrail and a published version must be READY before resource-policy calls.
    status = _poll_until(
        lambda: bedrock.get_guardrail(guardrailIdentifier=guardrail_id)["status"],
        lambda status: status in ("READY", "FAILED"),
        timeout_s=60.0,
        interval_s=3.0,
    )
    assert status == "READY", f"expected the draft guardrail to reach READY, got {status!r}"

    version = bedrock.create_guardrail_version(guardrailIdentifier=guardrail_id)["version"]
    version_status = _poll_until(
        lambda: bedrock.get_guardrail(guardrailIdentifier=guardrail_id, guardrailVersion=version)["status"],
        lambda status: status in ("READY", "FAILED"),
        timeout_s=60.0,
        interval_s=3.0,
    )
    assert version_status == "READY", (
        f"expected guardrail version {version!r} to reach READY before exercising "
        f"PutResourcePolicy against it, got {version_status!r}"
    )

    malformed_doc = "{this is not valid json at all!!"
    code, message = _error(
        lambda: bedrock.put_resource_policy(resourceArn=guardrail_arn, resourcePolicy=malformed_doc)
    )
    assert code == "ValidationException", (
        f"expected a syntactically invalid policy document to be rejected with "
        f"ValidationException, got {code!r}: {message!r}"
    )
    assert message == _NONCONFORMING_MESSAGE, f"unexpected rejection message: {message!r}"

    # With no policy set, GetResourcePolicy succeeds with resourcePolicy="{}" rather than
    # raising ResourceNotFoundException, so parse the JSON instead of testing the raw string.
    import json as _json

    absent_resp = bedrock.get_resource_policy(resourceArn=guardrail_arn)
    absent_policy = _json.loads(absent_resp.get("resourcePolicy") or "{}")
    if absent_policy:
        raise AssertionError(absent_policy)

    # Guardrail resource policies support only Allow, an account-root Principal, and the
    # {ApplyGuardrail, GetGuardrail} action pair on the guardrail's own ARN.
    valid_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": ["bedrock:ApplyGuardrail", "bedrock:GetGuardrail"],
                "Resource": guardrail_arn,
            }
        ],
    }
    import json as _json

    try:
        bedrock.put_resource_policy(resourceArn=guardrail_arn, resourcePolicy=_json.dumps(valid_doc))
    except ClientError as err:
        msg = err.response["Error"].get("Message", "")
        if "does not conform" in msg:
            raise AssertionError(
                "PutResourcePolicy rejects even a documented-shape guardrail resource "
                "policy in this account with 'does not conform to the supported policy "
                "formats' -- empirically this account cannot store ANY valid guardrail "
                "RBP (likely because it is a standalone account outside an AWS "
                "Organization, a prerequisite this feature appears to require even for "
                "same-account sharing); the malformed-rejection and effect-absence "
                "assertions above already exercised PutResourcePolicy/GetResourcePolicy "
                "successfully, but the accept-and-round-trip half is not exercisable here."
            ) from err
        raise
    fetched = _json.loads(bedrock.get_resource_policy(resourceArn=guardrail_arn)["resourcePolicy"])
    assert fetched == valid_doc, f"expected the stored policy to match exactly what was put, got {fetched!r}"


def _error(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not observed within {timeout_s}s; last saw {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
