"""staging-label-cap-refuses-the-twenty-first-label-on-a-version."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "staging-label-cap-refuses-the-twenty-first-label-on-a-version"
GROUP = "state-machine"
SERVICES = ["secretsmanager"]

# The cap counts custom staging labels only; AWSCURRENT occupies no slot against it.
_DOCUMENTED_CUSTOM_LABEL_CAP = 20
# Attempt strictly more than the cap so an unenforced ceiling is detected rather than never probed.
_ATTEMPTS = _DOCUMENTED_CUSTOM_LABEL_CAP + 5
_REFUSAL_CODES = frozenset({"LimitExceededException"})


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """The 21st custom staging label on a version is refused with LimitExceededException (AWSCURRENT
    takes no slot), the refused label lands nowhere, and freeing a slot lets the same call succeed.

    Reference: https://docs.aws.amazon.com/secretsmanager/latest/userguide/whats-in-a-secret.html
    """
    sm = ctx.client("secretsmanager")

    name = ctx.unique_name("sim2real-behav-smlabelcap-")
    created = sm.create_secret(
        Name=name,
        SecretString="capped-value",
        Description="sim2real behavioral draft: the staging-label ceiling",
        Tags=_sim2real_tags(),
    )
    arn = created["ARN"]
    v1 = created["VersionId"]
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=arn, ForceDeleteWithoutRecovery=True))

    # Anchor the label-set union asserted below to what DescribeSecret reports.
    start = _stages(sm, arn, v1)
    assert start == ["AWSCURRENT"], (
        f"a fresh secret's only version must hold exactly ['AWSCURRENT'] before slots are counted; "
        f"DescribeSecret reported {start!r}"
    )

    labels = [f"SIM2REALCAP{i:02d}" for i in range(_ATTEMPTS)]
    accepted: list[str] = []
    refused_label = None
    refused_code = None
    refused_message = None
    # Attach until one is refused to locate the ceiling.
    for label in labels:
        try:
            sm.update_secret_version_stage(SecretId=arn, VersionStage=label, MoveToVersionId=v1)
        except ClientError as exc:
            refused_label = label
            refused_code = exc.response.get("Error", {}).get("Code")
            refused_message = exc.response.get("Error", {}).get("Message")
            break
        accepted.append(label)

    assert refused_label is not None, (
        f"the staging-label ceiling must be enforced: {_ATTEMPTS} custom labels were attached to a "
        f"single version and every one was accepted (documented cap is "
        f"{_DOCUMENTED_CUSTOM_LABEL_CAP}); the version now reports {_stages(sm, arn, v1)!r}"
    )
    assert refused_code in _REFUSAL_CODES, (
        f"the over-cap attachment of {refused_label!r} must be refused with one of "
        f"{sorted(_REFUSAL_CODES)} (the blessing pass narrows this to the single observed code); got "
        f"{refused_code!r}"
    )
    assert refused_message == "You exceeded the maximum number of staging labels allowed on a secret.", (
        f"unexpected over-cap refusal message: {refused_message!r}"
    )

    # The staging index lags a write by 1-2s; wait only for the last accepted label to land, so
    # the exact-count assertion below stays failable.
    at_refusal = _poll(
        lambda: _stages(sm, arn, v1),
        lambda s: not accepted or accepted[-1] in s,
        timeout_s=60.0,
        interval_s=2.0,
        description="the last accepted staging label to appear in the staging index",
    )
    assert len(accepted) == _DOCUMENTED_CUSTOM_LABEL_CAP, (
        f"exactly {_DOCUMENTED_CUSTOM_LABEL_CAP} custom labels must fit on a version regardless of "
        f"AWSCURRENT; {len(accepted)} were accepted ({accepted!r})"
    )
    assert len(at_refusal) == len(start) + _DOCUMENTED_CUSTOM_LABEL_CAP, (
        f"the refusal must have happened with exactly {len(start)} built-in plus "
        f"{_DOCUMENTED_CUSTOM_LABEL_CAP} custom labels on the version -- as reported by the target "
        f"itself; DescribeSecret reports {len(at_refusal)} ({at_refusal!r}) after {len(accepted)} "
        f"custom attachments succeeded"
    )
    assert set(at_refusal) == {*start, *accepted}, (
        f"the version's label set must be exactly AWSCURRENT plus every accepted custom label; "
        f"expected {sorted({*start, *accepted})!r}, DescribeSecret reports {sorted(at_refusal)!r}"
    )

    # Effect absent: the refused label exists nowhere on the secret.
    every_label = _all_labels(sm, arn)
    assert refused_label not in every_label, (
        f"the refused label {refused_label!r} must not have been attached to ANY version; the "
        f"secret's full label set is {sorted(every_label)!r}"
    )
    read_by_refused, read_message = _error_code(
        lambda: sm.get_secret_value(SecretId=arn, VersionStage=refused_label)
    )
    assert read_by_refused == "ResourceNotFoundException", (
        f"reading by the refused label must fail with ResourceNotFoundException, proving it names "
        f"nothing; got {read_by_refused!r}"
    )
    expected_read_message = (
        f"Secrets Manager can't find the specified secret value for staging label: {refused_label}"
    )
    assert read_message == expected_read_message, (
        f"expected {expected_read_message!r}, got {read_message!r}"
    )
    assert sm.get_secret_value(SecretId=arn)["SecretString"] == "capped-value", (
        "a refused label attachment must leave the secret readable"
    )

    # Free exactly one slot; the identical attachment must then succeed.
    victim = accepted[-1]
    sm.update_secret_version_stage(SecretId=arn, VersionStage=victim, RemoveFromVersionId=v1)
    freed = _poll(
        lambda: _stages(sm, arn, v1),
        lambda s: victim not in s,
        timeout_s=60.0,
        interval_s=2.0,
        description=f"the removal of {victim!r} to be reflected in the staging index",
    )
    assert len(freed) == len(start) + _DOCUMENTED_CUSTOM_LABEL_CAP - 1, (
        f"removing one label must free exactly one slot; the version now reports {len(freed)} labels "
        f"({freed!r})"
    )
    sm.update_secret_version_stage(SecretId=arn, VersionStage=refused_label, MoveToVersionId=v1)

    final = _stages(sm, arn, v1)
    assert refused_label in final, (
        f"the previously refused label must now be attached; DescribeSecret reports {final!r}"
    )
    assert victim not in final, (
        f"the removed label must stay removed; DescribeSecret reports {final!r}"
    )
    assert len(final) == len(start) + _DOCUMENTED_CUSTOM_LABEL_CAP, (
        f"the version must be back at exactly the ceiling; DescribeSecret reports {len(final)} "
        f"labels ({final!r})"
    )
    # The label index for GetSecretValue lags the attachment by a few seconds; bounded wait.
    deadline = time.monotonic() + 60.0
    while True:
        try:
            by_label = sm.get_secret_value(SecretId=arn, VersionStage=refused_label)
            break
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                raise
            if time.monotonic() >= deadline:
                raise
            time.sleep(2.0)
    assert by_label["VersionId"] == v1 and by_label["SecretString"] == "capped-value", (
        f"the newly attached label must resolve to the version it was attached to and serve its "
        f"bytes; GetSecretValue returned {by_label.get('VersionId')!r} / "
        f"{by_label.get('SecretString')!r}"
    )


def _sim2real_tags() -> list[dict[str, str]]:
    return [
        {"Key": "sim2real", "Value": CHECK},
        {"Key": "sim2real:managed", "Value": "true"},
    ]


def _stages(sm, arn: str, version_id: str) -> list[str]:
    """The labels DescribeSecret reports for one version; a missing version fails loudly."""
    index = sm.describe_secret(SecretId=arn)["VersionIdsToStages"]
    assert version_id in index, (
        f"the version {version_id} this check created must appear in VersionIdsToStages; the index "
        f"is {index!r}"
    )
    return index[version_id]


def _all_labels(sm, arn: str) -> set[str]:
    index = sm.describe_secret(SecretId=arn)["VersionIdsToStages"]
    return {label for stages in index.values() for label in stages}


def _error_code(fn):
    """Call fn(); return (Error.Code, Error.Message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"real AWS refuses this call, but it SUCCEEDED and returned {result!r}")


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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
