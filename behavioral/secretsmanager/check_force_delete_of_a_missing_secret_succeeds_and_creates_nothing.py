"""force-delete-of-a-missing-secret-succeeds-and-creates-nothing."""
from __future__ import annotations

import re

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "force-delete-of-a-missing-secret-succeeds-and-creates-nothing"
GROUP = "lifecycle"
SERVICES = ["secretsmanager"]

_NOT_FOUND = ("ResourceNotFoundException", "Secrets Manager can't find the specified secret.")


def _error(fn) -> tuple[str, str]:
    """(Error.Code, Error.Message) that ``fn`` raises. An unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code", ""), err.get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Force-deleting a never-created secret succeeds twice with Name, ARN and DeletionDate, which
    teardown code relies on; unforced it is ResourceNotFoundException, and afterwards neither
    DescribeSecret nor ListSecrets with IncludePlannedDeletion finds the name (no tombstone)."""
    sm = ctx.client("secretsmanager")
    missing = ctx.unique_name("sim2real-behav-smforce-")
    arn_shape = re.compile(
        rf"arn:aws:secretsmanager:{re.escape(ctx.region)}:{re.escape(ctx.account)}:secret:"
        rf"{re.escape(missing)}-[A-Za-z0-9]{{6}}"
    )

    for attempt in (1, 2):
        resp = sm.delete_secret(SecretId=missing, ForceDeleteWithoutRecovery=True)
        assert resp["Name"] == missing, f"forced delete #{attempt} answered Name {resp['Name']!r}, expected {missing!r}"
        assert arn_shape.fullmatch(resp["ARN"]), (
            f"forced delete #{attempt} answered an ARN not of the form secret:<name>-XXXXXX in this "
            f"region and account (length {len(resp['ARN'])})"
        )
        assert resp.get("DeletionDate") is not None, f"forced delete #{attempt} answered no DeletionDate: {sorted(resp)!r}"

    unforced = _error(lambda: sm.delete_secret(SecretId=missing))
    assert unforced == _NOT_FOUND, f"DeleteSecret without the force flag returned {unforced!r}, expected {_NOT_FOUND!r}"

    after = _error(lambda: sm.describe_secret(SecretId=missing))
    assert after == _NOT_FOUND, f"after the forced deletes DescribeSecret returned {after!r}: a secret was created"
    listed = [
        s["Name"]
        for page in sm.get_paginator("list_secrets").paginate(
            Filters=[{"Key": "name", "Values": [missing]}], IncludePlannedDeletion=True
        )
        for s in page["SecretList"]
    ]
    assert listed == [], f"ListSecrets with IncludePlannedDeletion found {len(listed)} secret(s) under the name"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
