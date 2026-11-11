"""get-account-information-fields-present."""
from __future__ import annotations

import datetime
import re

from behavioral_harness import tags

CHECK = "get-account-information-fields-present"
GROUP = "state"
SERVICES = ["account"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetAccountInformation returns the caller's own AccountId (matching STS), a non-empty
    AccountName, a creation timestamp between 2002 and now, and AccountState ACTIVE, the only
    state an account that can make the call is in."""
    account = ctx.client("account")
    sts = ctx.client("sts")

    caller_account_id = sts.get_caller_identity()["Account"]
    info = account.get_account_information()

    assert re.fullmatch(r"\d{12}", info["AccountId"]), info["AccountId"]
    assert info["AccountId"] == caller_account_id, (info["AccountId"], caller_account_id)
    assert len(info["AccountName"]) >= 1, info["AccountName"]
    assert isinstance(info["AccountCreatedDate"], datetime.datetime), info["AccountCreatedDate"]
    aws_launch = datetime.datetime(2002, 1, 1, tzinfo=datetime.timezone.utc)
    now = datetime.datetime.now(datetime.timezone.utc)
    assert aws_launch < info["AccountCreatedDate"] < now, (info["AccountCreatedDate"], aws_launch, now)
    assert info["AccountState"] == "ACTIVE", info["AccountState"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
