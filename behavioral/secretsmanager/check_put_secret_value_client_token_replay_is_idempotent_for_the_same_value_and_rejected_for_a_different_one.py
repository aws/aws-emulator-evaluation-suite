"""put-secret-value-client-token-replay-is-idempotent-for-the-same-value-and-rejected-for-a-different-one."""

from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-secret-value-client-token-replay-is-idempotent-for-the-same-value-and-rejected-for-a-different-one"

GROUP = "overly-permissive"

SERVICES = ["secretsmanager"]

_SCENARIO = "secretsmanager-token-replay"


@tags(
    "axis:rejection",
    "cap:c4",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """PutSecretValue replaying a ClientRequestToken with identical content returns the same
    VersionId; with different content it is refused with ResourceExistsException. Neither replay
    mints a version or moves AWSCURRENT, and a fresh token still mints.
    """
    sm = ctx.client("secretsmanager")

    name = ctx.unique_name("sim2real-behav-tokreplay-")
    v1, v2, v3 = "credential-v1", "credential-v2", "credential-v3"

    created = sm.create_secret(
        Name=name,
        SecretString=v1,
        Description="sim2real behavioral check: ClientRequestToken replay semantics",
        Tags=_sim2real_tags(_SCENARIO),
    )
    arn = created["ARN"]
    ctx.on_cleanup(lambda: _reap_secret(ctx, arn))

    v1_version = created["VersionId"]
    assert _current(sm, arn)["SecretString"] == v1, "baseline: the created value must be AWSCURRENT"

    versions_at_start = _all_version_ids(sm, arn)
    assert versions_at_start == {v1_version}, (
        f"a freshly created secret must hold exactly its one version, saw {versions_at_start!r}"
    )

    token = uuid.uuid4().hex
    v2_resp = sm.put_secret_value(SecretId=arn, SecretString=v2, ClientRequestToken=token)
    assert v2_resp["VersionId"] != v1_version, (
        f"the first PutSecretValue under a new token must mint a new version, but it returned the "
        f"pre-existing {v1_version!r}"
    )
    versions_after_first = _all_version_ids(sm, arn)

    replay_same = sm.put_secret_value(SecretId=arn, SecretString=v2, ClientRequestToken=token)
    assert replay_same["VersionId"] == v2_resp["VersionId"], (
        f"replaying a token with identical content must be idempotent and return the same version: "
        f"{replay_same['VersionId']!r} != {v2_resp['VersionId']!r}"
    )
    versions_after_replay = _all_version_ids(sm, arn)
    assert versions_after_replay == versions_after_first, (
        f"an idempotent replay minted a second version: {sorted(versions_after_replay)!r} vs "
        f"{sorted(versions_after_first)!r}"
    )

    conflict_code, conflict_message = _error_code(
        lambda: sm.put_secret_value(
            SecretId=arn, SecretString="a-completely-different-credential", ClientRequestToken=token
        )
    )
    assert conflict_code == "ResourceExistsException", (
        f"replaying a ClientRequestToken with different content must be refused with "
        f"ResourceExistsException, got code={conflict_code!r}"
    )
    assert conflict_message == _token_in_use_message(token, arn), f"unexpected conflict message: {conflict_message!r}"

    # The refused write minted no version and AWSCURRENT still holds v2.
    versions_after_conflict = _all_version_ids(sm, arn)
    assert versions_after_conflict == versions_after_first, (
        f"the rejected write minted a version: {sorted(versions_after_conflict)!r} vs "
        f"{sorted(versions_after_first)!r}"
    )
    current_after_conflict = _current(sm, arn)
    assert (
        current_after_conflict["SecretString"] == v2
        and current_after_conflict["VersionId"] == v2_resp["VersionId"]
    ), f"the rejected write changed AWSCURRENT: {current_after_conflict['VersionId']!r} holding {current_after_conflict['SecretString']!r}"

    # Positive control: a fresh token still mints.
    fresh_resp = sm.put_secret_value(
        SecretId=arn, SecretString=v3, ClientRequestToken=uuid.uuid4().hex
    )
    assert fresh_resp["VersionId"] not in (v1_version, v2_resp["VersionId"]), (
        f"positive control: a fresh token must mint a new version, got the existing "
        f"{fresh_resp['VersionId']!r}"
    )
    get_after_fresh = _current(sm, arn)
    assert get_after_fresh["SecretString"] == v3, (
        f"positive control: the freshly written value must be current, AWSCURRENT holds "
        f"{get_after_fresh['SecretString']!r}"
    )
    assert get_after_fresh["VersionId"] == fresh_resp["VersionId"], (
        f"positive control: AWSCURRENT must point at the version PutSecretValue returned: "
        f"{get_after_fresh['VersionId']!r} != {fresh_resp['VersionId']!r}"
    )


def _sim2real_tags(scenario: str) -> list[dict[str, str]]:
    """Ownership tags for this check's resources."""
    return [
        {"Key": "sim2real", "Value": scenario},
        {"Key": "sim2real:managed", "Value": "true"},
    ]


def _error_code(fn):
    """Call fn(); return (Error.Code, Error.Message); an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"real AWS refuses this call, but it SUCCEEDED and returned {result!r}")


def _token_in_use_message(token: str, secret_arn: str) -> str:
    """The ResourceExistsException message for a ClientRequestToken reused with other content."""
    return (
        f"You can't use ClientRequestToken {token} because that value is already in use for a "
        f"version of secret {secret_arn}."
    )


def _current(sm, secret_id: str) -> dict:
    """GetSecretValue with no VersionStage -- the AWSCURRENT default."""
    return sm.get_secret_value(SecretId=secret_id)


def _all_version_ids(sm, secret_id: str) -> set[str]:
    """Every version id, including deprecated ones, across all pages."""
    ids: set[str] = set()
    token = None
    while True:
        kwargs = {"SecretId": secret_id, "IncludeDeprecated": True}
        if token:
            kwargs["NextToken"] = token
        resp = sm.list_secret_version_ids(**kwargs)
        ids.update(v["VersionId"] for v in resp.get("Versions", []))
        token = resp.get("NextToken")
        if not token:
            return ids


def _reap_secret(ctx, secret_id: str, timeout_s: float = 60.0) -> None:
    """Force-delete a secret, retrying throttling, and poll until it is really gone.

    A plain DeleteSecret imposes a 7-30 day recovery window during which the secret still bills.
    """
    sm = ctx.client("secretsmanager")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            sm.delete_secret(SecretId=secret_id, ForceDeleteWithoutRecovery=True)
            break
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
    while time.monotonic() < deadline:
        try:
            sm.describe_secret(SecretId=secret_id)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                return
        time.sleep(2.0)
    raise RuntimeError(f"secret {secret_id} still present {timeout_s}s after "
        f"ForceDeleteWithoutRecovery; it bills $0.40/month until reaped")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
