"""concurrent-create-secret-idempotent-token."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _force_delete(sm, secret_id):
    try:
        sm.delete_secret(SecretId=secret_id, ForceDeleteWithoutRecovery=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise

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


def _concurrent_error_codes(results):
    codes = []
    for r in results:
        if isinstance(r, ClientError):
            codes.append(r.response.get('Error', {}).get('Code'))
        elif isinstance(r, BaseException):
            codes.append(type(r).__name__)
    return codes

CHECK = "concurrent-create-secret-idempotent-token"
GROUP = 'state-machine'
SERVICES = ['secretsmanager']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """N concurrent identical CreateSecret retries (same token+content) all resolve to one version."""
    sm = ctx.client("secretsmanager")
    name = ctx.unique_name("sim2real-behav-secret-")
    ctx.on_cleanup(lambda: _force_delete(sm, name))
    token = uuid.uuid4().hex

    def make_creator():
        def _create():
            return sm.create_secret(
                Name=name,
                SecretString="same-value",
                ClientRequestToken=token,
                Tags=[{"Key": "sim2real", "Value": CHECK}],
            )

        return _create

    n = 8
    results = _run_concurrent([make_creator() for _ in range(n)], timeout_s=90)
    successes = [r for r in results if not isinstance(r, BaseException)]
    error_codes = _concurrent_error_codes(results)

    assert len(successes) == n, (
        f"identical concurrent creates with the same idempotency token must all succeed, "
        f"got {len(successes)} successes, errors={error_codes}"
    )
    version_ids = {r["VersionId"] for r in successes}
    assert len(version_ids) == 1, (
        f"all racers must observe the same single version, got {len(version_ids)} distinct versions"
    )

    arns = {r["ARN"] for r in successes}
    assert len(arns) == 1, f"all racers must observe the same ARN, got {len(arns)} distinct ARNs"

    winner = next(iter(version_ids))

    # Independent reads at the destination: identical-token retries must not mint
    # extra versions, and the one version that exists must be the one every racer saw.
    versions = sm.list_secret_version_ids(SecretId=name, IncludeDeprecated=True)["Versions"]
    all_version_ids = {v["VersionId"] for v in versions}
    assert all_version_ids == {winner}, (
        f"identical-token racers must not mint any version besides the one they all "
        f"observed ({winner}), but the secret holds {sorted(all_version_ids)}"
    )
    current_holders = [
        v["VersionId"] for v in versions if "AWSCURRENT" in v.get("VersionStages", [])
    ]
    assert current_holders == [winner], (
        f"AWSCURRENT must sit on the racers' shared version {winner}, got {current_holders}"
    )

    current = sm.get_secret_value(SecretId=name)
    assert current["VersionId"] == winner, (
        f"get_secret_value must read back the racers' version {winner}, got {current['VersionId']}"
    )
    assert current["SecretString"] == "same-value", (
        f"get_secret_value must read back the original content, got {current['SecretString']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
