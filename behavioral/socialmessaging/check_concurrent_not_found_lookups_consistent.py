"""concurrent-not-found-lookups-consistent."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-not-found-lookups-consistent"
GROUP = "concurrency"
SERVICES = ["socialmessaging"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Ten concurrent GetLinkedWhatsAppBusinessAccount lookups of the same well-formed, nonexistent
    WABA id each fail with ResourceNotFoundException "Requested resource not found.", and
    ListLinkedWhatsAppBusinessAccounts still answers without listing that id."""
    sm = ctx.client("socialmessaging")
    nonexistent = "waba-00000000000000000000000000000000"

    def _lookup(_i):
        return _error_code(lambda: sm.get_linked_whatsapp_business_account(id=nonexistent))

    with ThreadPoolExecutor(max_workers=10) as pool:
        codes = list(pool.map(_lookup, range(10)))

    assert len(codes) == 10, f"expected 10 racer results, got {len(codes)}"
    not_found = ("ResourceNotFoundException", "Requested resource not found.")
    assert all(code == not_found for code in codes), codes

    # Positive control: the service answers other calls, so "every racer got
    # ResourceNotFoundException" cannot be confused with "every call to this service fails".
    response = sm.list_linked_whatsapp_business_accounts()
    assert "linkedAccounts" in response
    assert nonexistent not in [a.get("id") for a in response["linkedAccounts"]]


def _error_code(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    an emulator accepting a lookup real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
    raise AssertionError(
        f"real AWS rejects this lookup with ResourceNotFoundException, but it "
        f"SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
