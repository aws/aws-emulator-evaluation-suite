"""delete-guardrail-in-use-by-version-conflict."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-guardrail-in-use-by-version-conflict"
GROUP = "concurrency"
SERVICES = ["bedrock"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:bedrock-enforced-guardrail")
def run(ctx) -> None:
    """DeleteGuardrail on a guardrail whose version the account's enforced guardrail configuration
    targets returns the exact 'cannot be deleted' ValidationException and the guardrail stays readable;
    after DeleteEnforcedGuardrailConfiguration the same delete succeeds and the guardrail is gone.
    """
    bedrock = ctx.client("bedrock")

    prior = _get_enforced_config(bedrock)

    guardrail = bedrock.create_guardrail(
        name=ctx.unique_name("sim2real-bedrock-gr-"),
        blockedInputMessaging="Sorry, I can't help with that input.",
        blockedOutputsMessaging="Sorry, I can't help with that output.",
        wordPolicyConfig={"wordsConfig": [{"text": "sim2realblockedword"}]},
        tags=[{"key": "sim2real", "value": "delete-guardrail-in-use-by-version-conflict"}],
    )
    guardrail_id = guardrail["guardrailId"]
    guardrail_arn = guardrail["guardrailArn"]
    ctx.on_cleanup(lambda: _safe_delete_guardrail(bedrock, guardrail_arn))
    _wait_for_guardrail_ready(bedrock, guardrail_arn, timeout_s=60)

    version = bedrock.create_guardrail_version(guardrailIdentifier=guardrail_arn)["version"]
    _wait_for_guardrail_version_ready(bedrock, guardrail_arn, version, timeout_s=60)

    put_kwargs: dict = {
        "guardrailInferenceConfig": {"guardrailIdentifier": guardrail_arn, "guardrailVersion": version}
    }
    if prior is not None:
        put_kwargs["configId"] = prior["configId"]
    put_resp = bedrock.put_enforced_guardrail_configuration(**put_kwargs)
    config_id = put_resp["configId"]

    ctx.on_cleanup(lambda: _restore_enforced_config(bedrock, prior, config_id))

    got = _error(lambda: bedrock.delete_guardrail(guardrailIdentifier=guardrail_arn))
    expected = (
        "ValidationException",
        "The guardrail cannot be deleted because it is associated with an account-level or "
        "organization-level default guardrail configuration.",
    )
    assert got == expected, f"expected {expected!r}, got {got!r}"

    # effect absent: the guardrail is still there, unaffected by the rejected delete
    still_there = bedrock.get_guardrail(guardrailIdentifier=guardrail_arn)
    assert still_there["guardrailId"] == guardrail_id, (
        f"delete_guardrail must have had no effect while the enforcement reference exists; "
        f"expected get_guardrail to still report {guardrail_id!r}, got {still_there.get('guardrailId')!r}"
    )

    # break the enforcement reference, then the SAME delete succeeds (positive control)
    bedrock.delete_enforced_guardrail_configuration(configId=config_id)
    bedrock.delete_guardrail(guardrailIdentifier=guardrail_arn)
    _wait_for_guardrail_gone(bedrock, guardrail_arn, timeout_s=60)


def _get_enforced_config(bedrock):
    resp = bedrock.list_enforced_guardrails_configuration()
    items = resp.get("guardrailsConfig", [])
    if not items:
        return None
    item = items[0]
    return {
        "configId": item["configId"],
        "guardrailArn": item["guardrailArn"],
        "guardrailVersion": item["guardrailVersion"],
    }


def _restore_enforced_config(bedrock, prior, our_config_id: str) -> None:
    try:
        if prior is not None:
            bedrock.put_enforced_guardrail_configuration(
                configId=prior["configId"],
                guardrailInferenceConfig={
                    "guardrailIdentifier": prior["guardrailArn"],
                    "guardrailVersion": prior["guardrailVersion"],
                },
            )
        else:
            bedrock.delete_enforced_guardrail_configuration(configId=our_config_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _error(fn):
    """The AWS error (code, message) fn raises. Raises AssertionError if fn SUCCEEDS: an
    acceptance where AWS refuses must never read as an error-code mismatch."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError("the call was ACCEPTED where a refusal was expected")


def _wait_for_guardrail_ready(bedrock, guardrail_arn: str, timeout_s: float) -> None:
    deadline = time.monotonic() + timeout_s
    status = ""
    while time.monotonic() < deadline:
        status = bedrock.get_guardrail(guardrailIdentifier=guardrail_arn)["status"]
        if status == "READY":
            return
        time.sleep(2)
    raise AssertionError(f"guardrail did not reach READY within the timeout (last status: {status!r})")


def _wait_for_guardrail_version_ready(bedrock, guardrail_arn: str, version: str, timeout_s: float) -> None:
    deadline = time.monotonic() + timeout_s
    status = ""
    while time.monotonic() < deadline:
        status = bedrock.get_guardrail(guardrailIdentifier=guardrail_arn, guardrailVersion=version)["status"]
        if status == "READY":
            return
        time.sleep(2)
    raise AssertionError(
        f"guardrail version {version} did not reach READY within the timeout (last status: {status!r})"
    )


def _safe_delete_guardrail(bedrock, guardrail_arn: str) -> None:
    try:
        bedrock.delete_guardrail(guardrailIdentifier=guardrail_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _wait_for_guardrail_gone(bedrock, guardrail_arn: str, timeout_s: float) -> None:
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            bedrock.get_guardrail(guardrailIdentifier=guardrail_arn)
        except ClientError as err:
            if err.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(2)
    raise AssertionError("guardrail was not deleted within the timeout")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

