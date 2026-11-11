"""op-create-policy-malformed-document-rejected."""
from __future__ import annotations

import json
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-create-policy-malformed-document-rejected"
GROUP = 'overly-permissive'
SERVICES = ['iot']

_ALLOW_ALL_DOC = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "iot:Connect", "Resource": "*"}],
    }
)

def _err(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")

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
    """CreatePolicy with an invalid document fails with MalformedPolicyException and its
    exact message and creates nothing (GetPolicy: ResourceNotFoundException), while a
    well-formed document creates the policy."""
    iot = ctx.client("iot")

    good_name = ctx.unique_name("sim2real-behav-policy-good-")
    iot.create_policy(policyName=good_name, policyDocument=_ALLOW_ALL_DOC)
    ctx.on_cleanup(lambda _n=good_name: _delete_policy(iot, _n))
    got = iot.get_policy(policyName=good_name)
    assert got["policyName"] == good_name, f"expected positive control to persist, got {got}"

    name = ctx.unique_name("sim2real-behav-policy-malformed-")
    code, message = _err(
        lambda: iot.create_policy(
            policyName=name, policyDocument="this-is-not-json-at-all"
        )
    )
    assert code == "MalformedPolicyException", f"expected MalformedPolicyException, got {code}"
    expected = "Policy document is Malformed: Invalid policy syntax."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    not_found, message = _err(lambda: iot.get_policy(policyName=name))
    assert not_found == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException, got {not_found}"
    )
    expected = "Policy default version not found"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
