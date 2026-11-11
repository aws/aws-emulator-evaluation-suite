"""concurrent-verify-email-identity-is-idempotent."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-verify-email-identity-is-idempotent"
GROUP = 'identity'
SERVICES = ['ses']

def _unique_email(ctx, prefix="probe-"):
    return f"{ctx.unique_name('sim2real-behav-' + prefix)}@example.com"


def _run_concurrent(fns, *, timeout_s=60):
    import concurrent.futures
    results = [None] * len(fns)
    resolved = set()

    def _capture(fut, idx):
        try:
            results[idx] = fut.result()
        except Exception as exc:
            results[idx] = exc
        resolved.add(idx)
    ex = concurrent.futures.ThreadPoolExecutor(max_workers=max(1, len(fns)))
    try:
        future_to_idx = {ex.submit(fn): i for i, fn in enumerate(fns)}
        try:
            for fut in concurrent.futures.as_completed(future_to_idx, timeout=timeout_s):
                _capture(fut, future_to_idx[fut])
        except concurrent.futures.TimeoutError as timeout_exc:
            for fut, idx in future_to_idx.items():
                if idx in resolved:
                    continue
                if fut.done():
                    _capture(fut, idx)
                else:
                    fut.cancel()
                    results[idx] = timeout_exc
    finally:
        ex.shutdown(wait=False, cancel_futures=True)
    return results


def _concurrent_successes(results):
    return sum((1 for r in results if not isinstance(r, BaseException)))


def _concurrent_error_codes(results):
    codes = []
    for r in results:
        if isinstance(r, ClientError):
            codes.append(r.response.get('Error', {}).get('Code'))
        elif isinstance(r, BaseException):
            codes.append(type(r).__name__)
    return codes


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """VerifyEmailIdentity is idempotent under concurrency: every racing call succeeds and exactly one identity results.

    Unlike Create* APIs, VerifyEmailIdentity is an upsert — no AlreadyExists is ever raised.
    """
    ses = ctx.client("ses")
    email = _unique_email(ctx, "race-verify-")

    def verify():
        return ses.verify_email_identity(EmailAddress=email)

    results = _run_concurrent([verify for _ in range(6)], timeout_s=90)
    ctx.on_cleanup(lambda _n=email: ses.delete_identity(Identity=_n))

    codes = _concurrent_error_codes(results)
    assert codes == [], f"VerifyEmailIdentity must not raise under concurrency, got {codes}"
    assert _concurrent_successes(results) == 6, "expected all 6 concurrent verifies to succeed"

    identities = ses.list_identities(IdentityType="EmailAddress")["Identities"]
    assert identities.count(email) == 1, f"expected exactly one identity, got {identities.count(email)}"
    status = ses.get_identity_verification_attributes(Identities=[email])[
        "VerificationAttributes"
    ][email]["VerificationStatus"]
    assert status == "Pending", f"expected Pending status, got {status!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
