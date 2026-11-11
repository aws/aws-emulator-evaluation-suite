"""concurrent-put-secret-value-no-lost-versions."""
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

def _create_secret(sm, ctx, name=None, secret_string="initial-value", **kwargs):
    """Create a secret, register its force-delete teardown, and return the raw response."""
    if name is None:
        name = ctx.unique_name("sim2real-behav-" + "secret-")
    params = {"Name": name}
    if secret_string is not None:
        params["SecretString"] = secret_string
    params.update(kwargs)
    resp = sm.create_secret(**params)
    ctx.on_cleanup(lambda: _force_delete(sm, name))
    return resp

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

CHECK = "concurrent-put-secret-value-no-lost-versions"
GROUP = 'state-machine'
SERVICES = ['secretsmanager']

@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """N concurrent PutSecretValue calls (distinct content, distinct tokens) must not lose versions."""
    sm = ctx.client("secretsmanager")
    name = ctx.unique_name("sim2real-behav-secret-")
    _create_secret(sm, ctx, name=name, secret_string="initial")

    n = 8

    def make_putter(i: int):
        def _put():
            return sm.put_secret_value(
                SecretId=name,
                SecretString=f"concurrent-value-{i}",
                ClientRequestToken=uuid.uuid4().hex,
            )

        return _put

    results = _run_concurrent([make_putter(i) for i in range(n)], timeout_s=90)
    successes = [r for r in results if not isinstance(r, BaseException)]
    assert len(successes) == n, (
        f"expected all {n} concurrent puts to succeed, got {len(successes)}, "
        f"errors={_concurrent_error_codes(results)}"
    )

    version_ids = {r["VersionId"] for r in successes}
    assert len(version_ids) == n, "each concurrent put must mint a distinct version (no lost/merged writes)"

    # Only AWSCURRENT/AWSPREVIOUS keep a staging label after the race, so the other
    # racers' versions are deprecated -- they must still be durably recorded, which
    # is only visible with IncludeDeprecated=True.
    versions = sm.list_secret_version_ids(
        SecretId=name, IncludeDeprecated=True
    )["Versions"]
    all_version_ids = {v["VersionId"] for v in versions}
    assert version_ids <= all_version_ids, (
        f"every concurrently-written version must be durably recorded; "
        f"missing {sorted(version_ids - all_version_ids)}"
    )
    # exactly one version holds AWSCURRENT after the race settles
    current_holders = [
        v["VersionId"] for v in versions if "AWSCURRENT" in v.get("VersionStages", [])
    ]
    assert len(current_holders) == 1, (
        f"exactly one version must hold AWSCURRENT after concurrent writes, got {len(current_holders)}"
    )
    assert current_holders[0] in version_ids, (
        "the surviving AWSCURRENT must be one of the concurrently-written versions"
    )
    # and the readable value must correspond to that winner
    current = sm.get_secret_value(SecretId=name)
    assert current["VersionId"] == current_holders[0], (
        f"get_secret_value must read back the AWSCURRENT version; "
        f"expected {current_holders[0]}, got {current['VersionId']}"
    )
    assert current["SecretString"].startswith("concurrent-value-"), (
        f"the readable value must be one of the concurrently-written payloads, "
        f"got {current['SecretString']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
