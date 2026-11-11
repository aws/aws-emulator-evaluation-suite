"""op-delete-attached-policy-rejected."""
from __future__ import annotations

import json
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-delete-attached-policy-rejected"
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

def _delete_certificate(iot, cert_id):
    """Teardown: detach policies/things, deactivate, then force-delete; a missing certificate is clean."""
    try:
        cert_arn = iot.describe_certificate(certificateId=cert_id)[
            "certificateDescription"
        ]["certificateArn"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return
        raise
    try:
        for p in iot.list_attached_policies(target=cert_arn).get("policies", []):
            iot.detach_policy(policyName=p["policyName"], target=cert_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    try:
        for t in iot.list_principal_things(principal=cert_arn).get("things", []):
            try:
                iot.detach_thing_principal(thingName=t, principal=cert_arn)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    try:
        iot.update_certificate(certificateId=cert_id, newStatus="INACTIVE")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    try:
        iot.delete_certificate(certificateId=cert_id, forceDelete=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise

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
    """DeletePolicy must refuse while the policy is still attached to a principal."""
    iot = ctx.client("iot")

    # positive control: an unattached policy deletes cleanly, so the
    # DeleteConflictException asserted below cannot be "DeletePolicy always fails".
    scratch_name = ctx.unique_name("sim2real-behav-policy-scratch-")
    iot.create_policy(
        policyName=scratch_name,
        policyDocument=_ALLOW_ALL_DOC,
        tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda _n=scratch_name: _delete_policy(iot, _n))
    iot.delete_policy(policyName=scratch_name)
    code, message = _err(lambda: iot.get_policy(policyName=scratch_name))
    assert code == "ResourceNotFoundException", (
        f"positive control failed: unattached policy should delete cleanly, got {code}"
    )
    expected = "Policy default version not found"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    name = ctx.unique_name("sim2real-behav-policy-attached-")
    iot.create_policy(
        policyName=name,
        policyDocument=_ALLOW_ALL_DOC,
        tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda _n=name: _delete_policy(iot, _n))

    created = iot.create_keys_and_certificate(setAsActive=True)
    cert_id = created["certificateId"]
    cert_arn = created["certificateArn"]
    ctx.on_cleanup(lambda _n=cert_id: _delete_certificate(iot, _n))
    # a "cert" ARN is not a taggable resource type for TagResource (verified against
    # real AWS: InvalidRequestException "Invalid resource type in ARN: cert"), so the
    # certificate itself cannot carry the sim2real tag; the policy and its name prefix
    # remain the tag-search surface for finding leftovers.
    iot.attach_policy(policyName=name, target=cert_arn)

    code, message = _err(lambda: iot.delete_policy(policyName=name))
    assert code == "DeleteConflictException", f"expected DeleteConflictException, got {code}"
    expected = (
        "The policy cannot be deleted as the policy is attached to one or more principals "
        f"(name={name})"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # policy must still exist: the refused delete had no effect
    got_name = iot.get_policy(policyName=name)["policyName"]
    assert got_name == name, f"expected policy {name!r} to still exist, got {got_name!r}"

    # once detached the delete is allowed -> proves the refusal was state-based
    iot.detach_policy(policyName=name, target=cert_arn)
    iot.delete_policy(policyName=name)
    final_code, message = _err(lambda: iot.get_policy(policyName=name))
    assert final_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException after restore+delete, got {final_code}"
    )
    expected = "Policy default version not found"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
