"""account-name-pattern-boundary-accepted."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "account-name-pattern-boundary-accepted"
GROUP = "state"
SERVICES = ["account"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:account-name")
def run(ctx) -> None:
    """PutAccountName accepts the full ^[ -;=?-~]+$ punctuation range, including the codepoints at
    each sub-range edge (space, ';', '=', '?', '~'), and the exact name round-trips through
    GetAccountInformation."""
    account = ctx.client("account")

    original_name = account.get_account_information()["AccountName"]
    ctx.on_cleanup(lambda: account.put_account_name(AccountName=original_name))

    # boundary codepoints placed mid-string (not string-edge) so a service-side trim of
    # leading/trailing whitespace can never be mistaken for a pattern-matching defect;
    # interior punctuation from both ranges (parens from 0x20-0x3B, letters from 0x3F-0x7E)
    # keeps it a realistic name
    punctuated_name = "Sim2Real ;=?~ (QA)=Acct;01"
    account.put_account_name(AccountName=punctuated_name)

    deadline = time.time() + 60
    seen = None
    while time.time() < deadline:
        seen = account.get_account_information()["AccountName"]
        if seen == punctuated_name:
            break
        time.sleep(3)
    assert seen == punctuated_name, f"AccountName never converged to {punctuated_name!r}, last saw {seen!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
