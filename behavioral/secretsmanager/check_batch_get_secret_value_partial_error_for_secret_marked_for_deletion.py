"""batch-get-secret-value-partial-error-for-secret-marked-for-deletion."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "batch-get-secret-value-partial-error-for-secret-marked-for-deletion"
GROUP = "error-semantics"
SERVICES = ["secretsmanager"]


@tags(
    "axis:rejection",
    "cap:c2",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """BatchGetSecretValue reports a secret scheduled for deletion as a per-id Errors entry
    (InvalidRequestException, "marked for deletion") beside the other secrets' values, rather than
    failing the whole call or silently omitting it.
    """
    sm = ctx.client("secretsmanager")
    base = ctx.unique_name("sim2real-behav-smbatchdel-")
    name_ok = f"{base}-ok"
    name_del = f"{base}-del"
    tags_list = [
        {"Key": "sim2real", "Value": CHECK},
        {"Key": "sim2real:managed", "Value": "true"},
    ]

    ok = sm.create_secret(Name=name_ok, SecretString="ok-value", Tags=tags_list)
    ctx.on_cleanup(lambda: _force_delete(sm, ok["ARN"]))
    deleting = sm.create_secret(Name=name_del, SecretString="deleting-value", Tags=tags_list)
    ctx.on_cleanup(lambda: _force_delete(sm, deleting["ARN"]))

    sm.delete_secret(SecretId=deleting["ARN"])  # default 30-day recovery window; NOT forced

    _poll(
        lambda: sm.describe_secret(SecretId=deleting["ARN"]).get("DeletedDate") is not None,
        lambda got: got,
        timeout_s=60.0,
        interval_s=2.0,
        description="DeletedDate to appear on the secret scheduled for deletion",
    )

    resp = sm.batch_get_secret_value(SecretIdList=[ok["ARN"], deleting["ARN"]])
    values_by_name = {v["Name"]: v for v in resp.get("SecretValues", [])}
    errors_by_id = {e["SecretId"]: e for e in resp.get("Errors", [])}

    assert name_ok in values_by_name, (
        f"the live secret must appear in SecretValues, got names {sorted(values_by_name)}"
    )
    assert values_by_name[name_ok]["SecretString"] == "ok-value", (
        f"expected 'ok-value' for the live secret, got {values_by_name[name_ok].get('SecretString')!r}"
    )
    assert name_del not in values_by_name, (
        f"the secret scheduled for deletion must NOT appear in SecretValues, got names "
        f"{sorted(values_by_name)}"
    )

    assert deleting["ARN"] in errors_by_id, (
        f"the secret scheduled for deletion must appear in Errors by its ARN, got secret ids "
        f"{sorted(errors_by_id)}"
    )
    err = errors_by_id[deleting["ARN"]]
    assert err["ErrorCode"] == "InvalidRequestException", (
        f"unexpected ErrorCode for a secret scheduled for deletion: {err.get('ErrorCode')!r}"
    )
    assert err["Message"] == (
        "You can't perform this operation on the secret because it was marked for deletion."
    ), f"unexpected Errors[].Message for a secret scheduled for deletion: {err.get('Message')!r}"

    # Positive control: the same batch excluding the deleting secret reports no errors at all.
    clean = sm.batch_get_secret_value(SecretIdList=[ok["ARN"]])
    assert clean.get("Errors", []) == [], (
        f"a batch naming only live secrets must report no errors, got {clean.get('Errors')}"
    )
    assert [v["Name"] for v in clean["SecretValues"]] == [name_ok], (
        f"expected exactly the live secret, got {[v['Name'] for v in clean['SecretValues']]}"
    )


# ===== helpers =====


def _poll(probe, predicate, *, timeout_s, interval_s, description):
    """Bounded poll that raises on timeout."""
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


def _force_delete(sm, secret_id):
    """Force-delete without a recovery window; a secret already scheduled for deletion is
    restored first so the force delete can land."""
    try:
        sm.delete_secret(SecretId=secret_id, ForceDeleteWithoutRecovery=True)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        if code == "ResourceNotFoundException":
            return
        if code != "InvalidRequestException":
            raise
        sm.restore_secret(SecretId=secret_id)
        sm.delete_secret(SecretId=secret_id, ForceDeleteWithoutRecovery=True)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
