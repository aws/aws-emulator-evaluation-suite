"""batch-get-secret-value-returns-partial-results-with-a-per-secret-error-for-a-denied-secret."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "batch-get-secret-value-returns-partial-results-with-a-per-secret-error-for-a-denied-secret"

GROUP = "overly-permissive"

SERVICES = ["secretsmanager"]

_SCENARIO = "secretsmanager-batch-deny"


@tags(
    "axis:rejection",
    "cap:c7",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """With a resource-policy Deny on one of three secrets, BatchGetSecretValue returns the two
    readable plaintexts plus one AccessDeniedException Errors entry for the denied one, instead
    of failing the call; removing the Deny restores three values and empty Errors.
    """
    sm = ctx.client("secretsmanager")
    caller_arn = ctx.client("sts").get_caller_identity()["Arn"]

    names = [ctx.unique_name(f"sim2real-behav-batchdeny-{i}-") for i in ("a", "b", "c")]
    plaintexts = ["batch-plaintext-alpha", "batch-plaintext-bravo", "batch-plaintext-charlie"]
    arns: list[str] = []
    for name, plaintext in zip(names, plaintexts):
        created = sm.create_secret(
            Name=name,
            SecretString=plaintext,
            Description="sim2real behavioral check: BatchGetSecretValue per-entry denial",
            Tags=_sim2real_tags(_SCENARIO),
        )
        arns.append(created["ARN"])
        ctx.on_cleanup(lambda a=created["ARN"]: _reap_secret(ctx, a))
    arn1, arn2, arn3 = arns
    expected = dict(zip(arns, plaintexts))

    # --- baseline: all three readable in one batch --------------------------------------------
    baseline = _batch_get(sm, arns)
    assert len(baseline["SecretValues"]) == 3 and not baseline["Errors"], (
        f"baseline: all three secrets must be readable before the Deny is applied, got "
        f"{len(baseline['SecretValues'])} values and errors={baseline['Errors']!r}"
    )

    # --- break exactly one thing: an explicit Deny on secret #2 only --------------------------
    deny_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "sim2realDenyReads",
                "Effect": "Deny",
                "Principal": {"AWS": "*"},
                "Action": [
                    "secretsmanager:GetSecretValue",
                    "secretsmanager:BatchGetSecretValue",
                ],
                "Resource": "*",
            }
        ],
    }
    sm.put_resource_policy(SecretId=arn2, ResourcePolicy=json.dumps(deny_policy))
    ctx.on_cleanup(lambda: _delete_resource_policy(ctx, arn2))

    # Resource policies are eventually consistent; wait for the single-secret read to be denied.
    single_code, single_message = _poll_until(
        lambda: _error(lambda: sm.get_secret_value(SecretId=arn2)),
        lambda err: err[0] == "AccessDeniedException",
        timeout_s=90.0,
        interval_s=3.0,
        description=(
            f"the resource-policy Deny on {arn2} to become effective on GetSecretValue "
            f"(caller {caller_arn})"
        ),
    )
    assert single_code == "AccessDeniedException", (
        f"the Deny must surface as AccessDeniedException on the single-secret read before the "
        f"batch semantics can mean anything, got {single_code!r}"
    )
    expected_message = (
        f"User: {caller_arn} is not authorized to perform: secretsmanager:GetSecretValue on "
        f"resource: {arn2} with an explicit deny in a resource-based policy"
    )
    assert single_message == expected_message, (
        f"the single-secret denial must name the caller, action, secret and explicit deny: "
        f"expected {expected_message!r}, got {single_message!r}"
    )

    # --- observe the partition ----------------------------------------------------------------
    resp = _batch_get(sm, arns)

    returned = {v["ARN"] for v in resp["SecretValues"]}
    assert returned == {arn1, arn3}, (
        f"the two permitted secrets must still be returned and the denied one must not be: "
        f"got {sorted(returned)!r}, expected {sorted([arn1, arn3])!r}"
    )
    assert len(resp["Errors"]) == 1, (
        f"the denied secret must appear in Errors, not be silently dropped: {resp['Errors']!r}"
    )
    entry = resp["Errors"][0]
    assert entry["SecretId"] == arn2, (
        f"the Errors entry must name the denied secret by the ARN it was requested as: {entry!r} "
        f"(expected {arn2!r})"
    )
    assert entry["ErrorCode"] == "AccessDeniedException", (
        f"the per-entry error code must be the authorization code, not a generic one: {entry!r}"
    )
    assert entry.get("Message") == expected_message, (
        f"the per-entry message must name the caller, action, secret and explicit deny: "
        f"expected {expected_message!r}, got {entry.get('Message')!r}"
    )
    assert all(v["SecretString"] == expected[v["ARN"]] for v in resp["SecretValues"]), (
        "the permitted secrets must return their real plaintexts, not placeholders: "
        + repr({v["ARN"]: v["SecretString"] for v in resp["SecretValues"]})
    )

    # --- positive control: remove the one broken thing, same call ------------------------------
    sm.delete_resource_policy(SecretId=arn2)
    after = _poll_until(
        lambda: _batch_get(sm, arns),
        lambda r: len(r["SecretValues"]) == 3 and not r["Errors"],
        timeout_s=90.0,
        interval_s=3.0,
        description="the batch read to recover after the resource policy was deleted",
    )
    assert len(after["SecretValues"]) == 3 and not after["Errors"], (
        f"positive control: removing the policy must restore a clean batch read: "
        f"{len(after['SecretValues'])} values, errors={after['Errors']!r}"
    )
    assert {v["ARN"]: v["SecretString"] for v in after["SecretValues"]} == expected, (
        "positive control: every plaintext must come back byte-identical: "
        + repr({v["ARN"]: v["SecretString"] for v in after["SecretValues"]})
    )


def _sim2real_tags(scenario: str) -> list[dict[str, str]]:
    return [
        {"Key": "sim2real", "Value": scenario},
        {"Key": "sim2real:managed", "Value": "true"},
    ]


_SUCCEEDED = "<call succeeded>"


def _error(fn):
    """Call fn(); return (Error.Code, Error.Message). A SUCCESS returns (_SUCCEEDED, None), a code
    no AWS error can equal, so a poll keeps waiting and a final assert fails loudly."""
    try:
        fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    return _SUCCEEDED, None


def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    deadline = time.monotonic() + timeout_s
    last = probe()
    while not predicate(last):
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"waited {timeout_s}s for {description}; last observation was {last!r}"
            )
        time.sleep(interval_s)
        last = probe()
    return last


def _batch_get(sm, secret_ids: list[str]) -> dict:
    """BatchGetSecretValue over an explicit id list, paginated, normalised to
    {"SecretValues": [...], "Errors": [...]} so callers never have to guard a missing key."""
    values: list[dict] = []
    errors: list[dict] = []
    token = None
    while True:
        kwargs: dict = {"SecretIdList": secret_ids}
        if token:
            kwargs["NextToken"] = token
        resp = sm.batch_get_secret_value(**kwargs)
        values.extend(resp.get("SecretValues", []))
        errors.extend(resp.get("Errors", []))
        token = resp.get("NextToken")
        if not token:
            return {"SecretValues": values, "Errors": errors}


def _delete_resource_policy(ctx, secret_id: str) -> None:
    """Detach the policy BEFORE the secret is force-deleted, or the delete itself can be denied."""
    try:
        ctx.client("secretsmanager").delete_resource_policy(SecretId=secret_id)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        if code not in ("ResourceNotFoundException", "InvalidRequestException"):
            raise RuntimeError(
                f"delete_resource_policy({secret_id}) failed with {code}: {exc}"
            ) from exc


def _reap_secret(ctx, secret_id: str, timeout_s: float = 60.0) -> None:
    """Force-delete a secret and poll until it is gone.

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
