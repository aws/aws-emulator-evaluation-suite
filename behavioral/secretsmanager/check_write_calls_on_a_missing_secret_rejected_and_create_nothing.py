"""write-calls-on-a-missing-secret-rejected-and-create-nothing."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "write-calls-on-a-missing-secret-rejected-and-create-nothing"
GROUP = "error-semantics"
SERVICES = ["secretsmanager"]

_TAGS = [{"Key": "sim2real", "Value": CHECK}]
_NOT_FOUND = ("ResourceNotFoundException", "Secrets Manager can't find the specified secret.")


def _error(fn) -> tuple[str, str]:
    """(Error.Code, Error.Message) that ``fn`` raises. An unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code", ""), err.get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Writes and ListSecretVersionIds on a never-created secret name fail ResourceNotFoundException
    and upsert nothing, while the same calls succeed on a secret that exists.
    """
    sm = ctx.client("secretsmanager")
    missing = ctx.unique_name("sim2real-behav-smmiss-")
    ctx.on_cleanup(lambda: _force_delete(sm, missing))
    control = ctx.unique_name("sim2real-behav-smctl-")

    calls = {
        "PutSecretValue": lambda sid: sm.put_secret_value(SecretId=sid, SecretString="written"),
        "UpdateSecret": lambda sid: sm.update_secret(SecretId=sid, SecretString="updated"),
        "TagResource": lambda sid: sm.tag_resource(SecretId=sid, Tags=[{"Key": "team", "Value": "a"}]),
        "UntagResource": lambda sid: sm.untag_resource(SecretId=sid, TagKeys=["team"]),
        "ListSecretVersionIds": lambda sid: sm.list_secret_version_ids(SecretId=sid),
    }
    for op, call in calls.items():
        got = _error(lambda: call(missing))
        assert got == _NOT_FOUND, f"{op} on a never-created secret returned {got!r}, expected {_NOT_FOUND!r}"
    got = _error(lambda: sm.delete_secret(SecretId=missing, RecoveryWindowInDays=7))
    assert got == _NOT_FOUND, f"DeleteSecret on a never-created secret returned {got!r}, expected {_NOT_FOUND!r}"

    after = _error(lambda: sm.describe_secret(SecretId=missing))
    assert after == _NOT_FOUND, (
        f"after six refused writes DescribeSecret on the name returned {after!r}: a refused write created a secret"
    )
    listed = [
        s["Name"]
        for page in sm.get_paginator("list_secrets").paginate(
            Filters=[{"Key": "name", "Values": [missing]}], IncludePlannedDeletion=True
        )
        for s in page["SecretList"]
    ]
    assert listed == [], f"ListSecrets filtered to the missing name returned {len(listed)} secret(s)"

    created = sm.create_secret(Name=control, SecretString="initial", Tags=_TAGS)
    ctx.on_cleanup(lambda: _force_delete(sm, created["ARN"]))
    for op, call in calls.items():
        call(control)
    desc = sm.describe_secret(SecretId=control)
    assert {t["Key"] for t in desc.get("Tags", [])} == {"sim2real"}, (
        f"control secret tags after TagResource+UntagResource(team): {desc.get('Tags')!r}"
    )
    value = sm.get_secret_value(SecretId=control)["SecretString"]
    assert value == "updated", f"control secret value after PutSecretValue+UpdateSecret is {value!r}, expected 'updated'"
    deleted = sm.delete_secret(SecretId=control, RecoveryWindowInDays=7)
    assert deleted["Name"] == control, f"DeleteSecret on the control secret answered Name {deleted['Name']!r}"


def _force_delete(sm, secret_id: str) -> None:
    try:
        sm.delete_secret(SecretId=secret_id, ForceDeleteWithoutRecovery=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
