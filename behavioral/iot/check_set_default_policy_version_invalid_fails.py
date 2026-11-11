"""set-default-policy-version-invalid-fails."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "set-default-policy-version-invalid-fails"
GROUP = 'policy-lifecycle'
SERVICES = ['iot']

def _error(fn) -> tuple[str, str]:
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises rather
    than returning a falsy sentinel, so a target that accepts what AWS refuses fails loudly."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")

def _policy_doc(effect: str = "Allow", version: int = 1) -> str:
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": effect,
                    "Action": "iot:Connect",
                    "Resource": f"arn:aws:iot:*:*:client/probe-{version}",
                }
            ],
        }
    )

def _delete_policy(iot, name):
    """Best-effort teardown: delete non-default versions, detach targets, then delete a policy."""
    try:
        for v in iot.list_policy_versions(policyName=name).get("policyVersions", []):
            if not v.get("isDefaultVersion"):
                try:
                    iot.delete_policy_version(policyName=name, policyVersionId=v["versionId"])
                except ClientError as exc:
                    if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                        raise
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    try:
        for t in iot.list_targets_for_policy(policyName=name).get("targets", []):
            iot.detach_policy(policyName=name, target=t)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    try:
        iot.delete_policy(policyName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """SetDefaultPolicyVersion with a policyVersionId that never existed must fail with ResourceNotFoundException."""
    iot = ctx.client("iot")
    policy_name = ctx.unique_name("sim2real-behav-policy-badver-")
    iot.create_policy(
        policyName=policy_name,
        policyDocument=_policy_doc(),
        tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda _n=policy_name: _delete_policy(iot, _n))

    # Positive control: a real version must be settable as default, so a target that
    # rejects every SetDefaultPolicyVersion call cannot pass this check by accident.
    v2 = iot.create_policy_version(policyName=policy_name, policyDocument=_policy_doc(version=2), setAsDefault=False)
    iot.set_default_policy_version(policyName=policy_name, policyVersionId=v2["policyVersionId"])
    after_control = iot.get_policy(policyName=policy_name)
    assert after_control["defaultVersionId"] == v2["policyVersionId"], (
        f"expected default version {v2['policyVersionId']!r}, got {after_control['defaultVersionId']!r}"
    )

    code, code_message = _error(
        lambda: iot.set_default_policy_version(policyName=policy_name, policyVersionId="99")
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    assert code_message == f"Policy version does not exist (name={policy_name}, versionId=99)", (
        f"expected the exact {code} message, got {code_message!r}"
    )

    # Effect absent: an independent read at the destination shows the failed call left
    # the default version exactly where the positive control put it.
    after_invalid = iot.get_policy(policyName=policy_name)
    assert after_invalid["defaultVersionId"] == v2["policyVersionId"], (
        f"expected default version to remain {v2['policyVersionId']!r}, "
        f"got {after_invalid['defaultVersionId']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
