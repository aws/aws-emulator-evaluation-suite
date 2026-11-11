"""describe-backup-not-found-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-backup-not-found-rejected"
GROUP = "error-semantics"
SERVICES = ["dynamodb"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeBackup with an unknown backup ARN returns BackupNotFoundException."""
    ddb = ctx.client("dynamodb")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    fake_table = ctx.unique_name("sim2real-notable-")
    # Real DynamoDB backup ids are a 14-digit (zero-padded) millisecond epoch timestamp,
    # a dash, and an 8-character hex suffix (e.g. "01639426382000-1509b1b3"). A backup id
    # of the wrong shape (e.g. only 12 digits) is rejected by ARN-shape validation with a
    # generic ValidationException *before* DynamoDB ever looks up whether a backup with
    # that id exists — so it never reaches BackupNotFoundException. Use a well-formed but
    # nonexistent id so the request actually exercises the not-found lookup.
    fake_backup_id = f"0{int(time.time() * 1000)}-abcdef01"
    fake_arn = (
        f"arn:aws:dynamodb:{ctx.region}:{account_id}:table/{fake_table}/backup/{fake_backup_id}"
    )

    code, message = _error(lambda: ddb.describe_backup(BackupArn=fake_arn))
    assert code == "BackupNotFoundException", f"expected BackupNotFoundException, got {code}"
    expected_message = f"Backup not found: {fake_arn}"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _error(fn):
    """(code, message) of the ClientError fn raises; an unexpected success raises AssertionError."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
