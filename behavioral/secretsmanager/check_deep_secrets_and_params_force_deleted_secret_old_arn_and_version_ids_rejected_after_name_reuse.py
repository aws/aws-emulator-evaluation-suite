"""deep-secrets-and-params-force-deleted-secret-old-arn-and-version-ids-rejected-after-name-reuse."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-secrets-and-params-force-deleted-secret-old-arn-and-version-ids-rejected-after-name-reuse"

GROUP = "deletion"

SERVICES = ["secretsmanager"]

_SCENARIO = "deep-secrets-force-delete-identity"


@tags(
    "axis:rejection",
    "cap:c2",
    "cap:c4",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:control",
    "plane:data",
)
def run(ctx) -> None:
    """A scheduled secret's name is reserved; after a force delete, a secret re-created under it
    gets a new ARN and fresh version ids, and the old ARN, old VersionIds and RestoreSecret of the
    old ARN are refused with ResourceNotFoundException.
    """
    sm = ctx.client("secretsmanager")
    name = ctx.unique_name("sim2real-deep-sm-")

    first = sm.create_secret(
        Name=name,
        SecretString="original-material",
        Description="sim2real behavioral check: force-deleted identity",
        Tags=_sim2real_tags(),
    )
    old_arn = first["ARN"]
    ctx.on_cleanup(lambda: _reap_secret(sm, old_arn))
    v1 = first["VersionId"]
    v2 = sm.put_secret_value(SecretId=old_arn, SecretString="second-material")["VersionId"]

    # --- the recovery window reserves the name ------------------------------------------------
    scheduled = sm.delete_secret(SecretId=old_arn, RecoveryWindowInDays=7)
    assert scheduled["ARN"] == old_arn and scheduled.get("DeletionDate") is not None, scheduled
    reserved = _error(lambda: sm.create_secret(Name=name, SecretString="usurper"))
    assert reserved.get("Code") == "InvalidRequestException", (
        f"while the secret is scheduled for deletion its name must be reserved "
        f"(InvalidRequestException), got {reserved!r}"
    )
    assert reserved.get("Message") == (
        "You can't create this secret because a secret with this name is already scheduled for "
        "deletion."
    ), f"unexpected name-reserved message: {reserved.get('Message')!r}"
    assert sm.describe_secret(SecretId=old_arn).get("DeletedDate") is not None, (
        "the refused create must leave the original still scheduled for deletion"
    )

    # --- ForceDeleteWithoutRecovery on the scheduled secret frees the name ---------------------
    forced = sm.delete_secret(SecretId=old_arn, ForceDeleteWithoutRecovery=True)
    assert forced["ARN"] == old_arn, forced

    second = _create_when_name_frees(ctx, sm, name)
    new_arn = second["ARN"]
    ctx.on_cleanup(lambda: _reap_secret(sm, new_arn))

    # Positive control: the new secret works through every handle that names IT.
    assert new_arn != old_arn, (
        f"a secret re-created after a force delete must get a NEW ARN, got the old one {old_arn!r}"
    )
    assert second["Name"] == name, second
    by_name = sm.get_secret_value(SecretId=name)
    by_new_arn = sm.get_secret_value(SecretId=new_arn)
    assert by_name["SecretString"] == "reborn-material" == by_new_arn["SecretString"], (
        f"the name and the new ARN must both serve the new value: {by_name['SecretString']!r} / "
        f"{by_new_arn['SecretString']!r}"
    )
    assert by_name["ARN"] == new_arn, f"the name must resolve to the new ARN, got {by_name['ARN']!r}"
    assert second["VersionId"] not in (v1, v2), (
        f"the new secret must mint fresh version ids, got {second['VersionId']!r}"
    )
    staged = sm.describe_secret(SecretId=new_arn)["VersionIdsToStages"]
    assert staged == {second["VersionId"]: ["AWSCURRENT"]}, (
        f"the re-created secret must carry exactly its own single version, got {staged!r}"
    )

    # --- the old identity is gone, through every handle that named it -------------------------
    not_found = "Secrets Manager can't find the specified secret."
    for label, call, expected_message in (
        ("get_secret_value(old ARN)", lambda: sm.get_secret_value(SecretId=old_arn), not_found),
        ("describe_secret(old ARN)", lambda: sm.describe_secret(SecretId=old_arn), not_found),
        ("get_secret_value(name, old VersionId v1)",
         lambda: sm.get_secret_value(SecretId=name, VersionId=v1),
         f"Secrets Manager can't find the specified secret value for VersionId: {v1}"),
        ("get_secret_value(name, old VersionId v2)",
         lambda: sm.get_secret_value(SecretId=name, VersionId=v2),
         f"Secrets Manager can't find the specified secret value for VersionId: {v2}"),
        ("restore_secret(old ARN)", lambda: sm.restore_secret(SecretId=old_arn), not_found),
    ):
        err = _error(call)
        assert err.get("Code") == "ResourceNotFoundException", (
            f"{label} must be refused with ResourceNotFoundException after a force delete and "
            f"name reuse, got {err!r}"
        )
        assert err.get("Message") == expected_message, (
            f"{label}: expected message {expected_message!r}, got {err.get('Message')!r}"
        )

    # Effect absent: none of those refused calls leaked the old material into the new secret.
    versions = [v["VersionId"] for v in sm.list_secret_version_ids(
        SecretId=new_arn, IncludeDeprecated=True)["Versions"]]
    assert versions == [second["VersionId"]], (
        f"the new secret must hold only its own version, got {versions!r}"
    )
    assert sm.get_secret_value(SecretId=name)["SecretString"] == "reborn-material", (
        "the name must still serve only the new material"
    )


def _sim2real_tags() -> list[dict[str, str]]:
    return [{"Key": "sim2real", "Value": _SCENARIO}, {"Key": "sim2real:managed", "Value": "true"}]


def _error(fn) -> dict:
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"the call was expected to be refused but SUCCEEDED: {result!r}")


def _create_when_name_frees(ctx, sm, name: str, timeout_s: float = 180.0):
    """Retry CreateSecret until the name frees; ForceDeleteWithoutRecovery is asynchronous.

    Only InvalidRequestException (the name is still reserved) is retried.
    """
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            return sm.create_secret(
                Name=name,
                SecretString="reborn-material",
                Description="sim2real behavioral check: force-deleted identity (reborn)",
                Tags=_sim2real_tags(),
            )
        except ClientError as exc:
            last = exc
            if exc.response.get("Error", {}).get("Code") != "InvalidRequestException":
                raise
            time.sleep(3.0)
    raise AssertionError(
        f"the name {name!r} never became creatable within {timeout_s}s of "
        f"ForceDeleteWithoutRecovery; last error: {last}"
    )


def _reap_secret(sm, secret_id: str, timeout_s: float = 60.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            sm.delete_secret(SecretId=secret_id, ForceDeleteWithoutRecovery=True)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "ResourceNotFoundException":
                return
            if code in ("ThrottlingException", "InternalServiceError"):
                time.sleep(2.0)
                continue
            teardown_code = exc.response.get("Error", {}).get("Code", "")
            if teardown_code not in ("ResourceNotFoundException",):
                raise RuntimeError(
                    f"delete_secret({secret_id}) failed with {code}: {exc}"
                ) from exc
            return
    raise RuntimeError(f"secret {secret_id} could not be force-deleted within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
