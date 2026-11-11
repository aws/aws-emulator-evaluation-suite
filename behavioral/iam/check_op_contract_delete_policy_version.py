"""op-contract-deletePolicyVersion."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-deletePolicyVersion"
GROUP = "error-semantics"
SERVICES = ["iam"]

_DOC_V1 = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "s3:ListBucket", "Resource": "*"}],
}
_DOC_V2 = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}],
}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeletePolicyVersion removes a non-default version; DeleteConflict on the default version
    (a state, not a permanent property of the VersionId) until a different version is promoted,
    after which the identical delete call succeeds; an unknown VersionId 404s."""
    iam = ctx.client("iam")

    policy_name = ctx.unique_name("sim2real-behav-polver-")
    created = iam.create_policy(PolicyName=policy_name, PolicyDocument=json.dumps(_DOC_V1))
    arn = created["Policy"]["Arn"]
    default_version_id = created["Policy"]["DefaultVersionId"]
    ctx.on_cleanup(lambda: iam.delete_policy(PolicyArn=arn))

    v2 = iam.create_policy_version(PolicyArn=arn, PolicyDocument=json.dumps(_DOC_V2), SetAsDefault=False)
    v2_id = v2["PolicyVersion"]["VersionId"]
    assert v2["PolicyVersion"]["IsDefaultVersion"] is False, (
        f"expected new version not default, got {v2['PolicyVersion']['IsDefaultVersion']}"
    )

    # success path: delete the non-default version
    resp = iam.delete_policy_version(PolicyArn=arn, VersionId=v2_id)
    assert resp["ResponseMetadata"]["HTTPStatusCode"] == 200, (
        f"expected 200 on delete, got {resp['ResponseMetadata']['HTTPStatusCode']}"
    )
    remaining_ids = [v["VersionId"] for v in iam.list_policy_versions(PolicyArn=arn)["Versions"]]
    assert v2_id not in remaining_ids, f"expected {v2_id} gone after delete, still in {remaining_ids}"
    assert default_version_id in remaining_ids, (
        f"expected {default_version_id} to remain, got {remaining_ids}"
    )

    # a second non-default version, so the default can later be reassigned off default_version_id
    v3 = iam.create_policy_version(PolicyArn=arn, PolicyDocument=json.dumps(_DOC_V2), SetAsDefault=False)
    v3_id = v3["PolicyVersion"]["VersionId"]

    # error boundary: attempting to delete the current default version is rejected
    conflict_code, conflict_msg = _client_error(
        lambda: iam.delete_policy_version(PolicyArn=arn, VersionId=default_version_id)
    )
    assert conflict_code == "DeleteConflict", f"expected DeleteConflict, got {conflict_code}"
    assert conflict_msg == "Cannot delete the default version of a policy.", f"unexpected DeleteConflict message {conflict_msg!r}"
    ids_after_conflict = [v["VersionId"] for v in iam.list_policy_versions(PolicyArn=arn)["Versions"]]
    assert default_version_id in ids_after_conflict, (
        f"rejected delete must not remove the version: expected {default_version_id} still "
        f"present, got {ids_after_conflict}"
    )

    # restore: promote the other version to default, then the SAME VersionId that was just
    # rejected becomes deletable
    iam.set_default_policy_version(PolicyArn=arn, VersionId=v3_id)
    iam.delete_policy_version(PolicyArn=arn, VersionId=default_version_id)
    ids_after_restore = [v["VersionId"] for v in iam.list_policy_versions(PolicyArn=arn)["Versions"]]
    assert default_version_id not in ids_after_restore, (
        f"expected {default_version_id} deletable once no longer default, still in {ids_after_restore}"
    )
    assert ids_after_restore == [v3_id], f"expected only {v3_id} to remain, got {ids_after_restore}"

    # distinct boundary: an unknown VersionId 404s
    nf_code, nf_msg = _client_error(lambda: iam.delete_policy_version(PolicyArn=arn, VersionId="v99"))
    assert nf_code == "NoSuchEntity", f"expected NoSuchEntity, got {nf_code}"
    assert nf_msg == f"Policy {arn} version v99 does not exist or is not attachable.", f"unexpected NoSuchEntity message {nf_msg!r}"


def _client_error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
