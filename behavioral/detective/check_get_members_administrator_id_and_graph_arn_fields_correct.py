"""get-members-administrator-id-and-graph-arn-fields-correct."""
from __future__ import annotations

import time
import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "get-members-administrator-id-and-graph-arn-fields-correct"
GROUP = "state"
SERVICES = ["detective"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:detective-graph")
def run(ctx) -> None:
    """GetMembers reports the correct AdministratorId (the caller) and GraphArn for an invited member."""
    d = ctx.client("detective")
    arn = _create_graph_with_retry(d)
    # NOTE: an account can administer only one behavior graph per Region, so this graph is
    # shared with other checks in the suite run; it is intentionally not deleted here.
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    fake_account_id = _fake_account_id(ctx)
    fake_email = f"sim2real-detective-{uuid.uuid4().hex[:10]}@example.com"
    d.create_members(
        GraphArn=arn,
        Accounts=[{"AccountId": fake_account_id, "EmailAddress": fake_email}],
        DisableEmailNotification=True,
    )
    ctx.on_cleanup(lambda: _delete_members_quietly(d, arn, [fake_account_id]))

    resp = d.get_members(GraphArn=arn, AccountIds=[fake_account_id])
    details = resp["MemberDetails"]
    assert len(details) == 1, f"expected exactly one member, got {details!r}"
    member = details[0]
    assert member["AdministratorId"] == account_id, (
        f"expected AdministratorId {account_id!r}, got {member['AdministratorId']!r}"
    )
    assert member["GraphArn"] == arn, f"expected GraphArn {arn!r}, got {member['GraphArn']!r}"
    # The fake account ID does not correspond to a real AWS account, so Detective's
    # account/email verification fails immediately and InvitationType is only populated once
    # verification succeeds -- assert the verification-failure status instead.
    assert member["Status"] in ("VERIFICATION_IN_PROGRESS", "VERIFICATION_FAILED"), (
        f"unexpected status for an unverifiable fake account: {member!r}"
    )


def _create_graph_with_retry(d, retries: int = 8, base_delay: float = 5.0) -> str:
    from botocore.exceptions import ClientError

    for attempt in range(retries):
        try:
            return d.create_graph()["GraphArn"]
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("TooManyRequestsException", "ThrottlingException") and attempt < retries - 1:
                time.sleep(base_delay * (attempt + 1))
                continue
            raise
    raise AssertionError("create_graph did not succeed after retries")


def _delete_members_quietly(d, graph_arn: str, account_ids: list[str]) -> None:
    from botocore.exceptions import ClientError

    try:
        d.delete_members(GraphArn=graph_arn, AccountIds=account_ids)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _fake_account_id(ctx) -> str:
    import random

    real_account = ctx.client("sts").get_caller_identity()["Account"]
    while True:
        candidate = "9" + "".join(str(random.randint(0, 9)) for _ in range(11))
        if candidate != real_account:
            return candidate


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
