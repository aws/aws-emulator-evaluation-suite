"""automated-backup-arn-param-malformed-rejected."""
from __future__ import annotations

import secrets
import string
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "automated-backup-arn-param-malformed-rejected"
GROUP = "instance_lifecycle"
SERVICES = ["rds"]

_ALPHABET = string.ascii_lowercase + string.digits


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteDBInstanceAutomatedBackup and DescribeDBInstanceAutomatedBackups both refuse a
    DBInstanceAutomatedBackupsArn that is not a valid automated-backup ARN; a well-formed but
    unknown identifier is instead rejected as not found.

    Reference: https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_DeleteDBInstanceAutomatedBackup.html
    """
    rds = ctx.client("rds")

    bogus_id = "ab-" + "".join(secrets.choice(_ALPHABET) for _ in range(40))
    malformed_arn = f"arn:aws:rds:{ctx.region}:{ctx.account}:auto-backup:{bogus_id}"

    delete_code, delete_message = _error(
        lambda: rds.delete_db_instance_automated_backup(DBInstanceAutomatedBackupsArn=malformed_arn)
    )
    assert delete_code == "InvalidParameterValue", f"unexpected error code: {delete_code}"
    assert delete_message == (
        f"The provided ARN ({malformed_arn}) is invalid for this parameter (DbInstanceAutomatedBackupsArn)."
    ), delete_message

    describe_code, describe_message = _error(
        lambda: rds.describe_db_instance_automated_backups(DBInstanceAutomatedBackupsArn=malformed_arn)
    )
    assert describe_code == "InvalidParameterValue", f"unexpected error code: {describe_code}"
    assert describe_message == (
        f"The provided ARN ({bogus_id}) is invalid for this parameter (DbInstanceAutomatedBackupsArn)."
    ), describe_message

    # Positive control: a well-formed identifier of the right shape is parsed, and only then
    # reported not found -- the same two operations, the one broken thing (the ARN's shape) fixed.
    bogus_resource_id = "db-" + uuid.uuid4().hex[:26].upper()
    found_delete_code, found_delete_message = _error(
        lambda: rds.delete_db_instance_automated_backup(DbiResourceId=bogus_resource_id)
    )
    assert found_delete_code == "DBInstanceAutomatedBackupNotFound", (
        f"unexpected error code: {found_delete_code}"
    )
    assert found_delete_message == f"Automated backups could not be found for: {bogus_resource_id}", (
        found_delete_message
    )

    found_describe_code, found_describe_message = _error(
        lambda: rds.describe_db_instance_automated_backups(DbiResourceId=bogus_resource_id)
    )
    assert found_describe_code == "DBInstanceAutomatedBackupNotFound", (
        f"unexpected error code: {found_describe_code}"
    )
    assert found_describe_message == (
        f"DBInstanceAutomatedBackup for DBInstance {bogus_resource_id} not found."
    ), found_describe_message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
