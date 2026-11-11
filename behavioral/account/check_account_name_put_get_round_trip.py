"""account-name-put-get-round-trip."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "account-name-put-get-round-trip"
GROUP = "state"
SERVICES = ["account"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:account-name")
def run(ctx) -> None:
    """PutAccountName overwrites the account name and it is (eventually) reflected by
    GetAccountInformation. The write itself is accepted synchronously, but propagation
    to reads can lag, so poll to the new value with a bounded timeout."""
    account = ctx.client("account")

    original_name = account.get_account_information()["AccountName"]
    ctx.on_cleanup(lambda: account.put_account_name(AccountName=original_name))

    new_name = ctx.unique_name("sim2real-behav-acct-")
    account.put_account_name(AccountName=new_name)

    deadline = time.time() + 60
    seen = None
    while time.time() < deadline:
        seen = account.get_account_information()["AccountName"]
        if seen == new_name:
            break
        time.sleep(3)
    assert seen == new_name, f"AccountName never converged to {new_name!r}, last saw {seen!r}"
    assert seen != original_name, (
        f"expected AccountName to differ from the pre-write value {original_name!r}, got {seen!r}"
    )

    for _ in range(2):
        time.sleep(2)
        reread = account.get_account_information()["AccountName"]
        assert reread == new_name, (
            f"AccountName reverted to {reread!r} after converging to {new_name!r} -- "
            "read is not stable"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
