"""concurrent-delete-supplemental-tax-registration-consistent."""
from __future__ import annotations

import concurrent.futures as cf

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-delete-supplemental-tax-registration-consistent"
GROUP = "concurrency"
SERVICES = ["taxsettings"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Concurrent DeleteSupplementalTaxRegistration calls for the same malformed authorityId all fail with
    ValidationException "Provided authorityId is not valid.", with no other outcome under concurrency."""
    ts = ctx.client("taxsettings")
    n = 8
    bogus_authority = ctx.unique_name("sim2real-concurrent-no-such-authority-")

    def attempt(_i: int):
        try:
            ts.delete_supplemental_tax_registration(authorityId=bogus_authority)
            return "ok"
        except ClientError as exc:
            return exc.response["Error"]["Code"], exc.response["Error"].get("Message")

    with cf.ThreadPoolExecutor(max_workers=n) as pool:
        results = list(pool.map(attempt, range(n)))

    assert all(r[0] == "ValidationException" for r in results), (
        f"expected every concurrent call to see ValidationException consistently, got {results}"
    )
    assert all(r[1] == "Provided authorityId is not valid." for r in results), results


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)


