"""concurrent-developer-login-leaves-the-pool-with-exactly-one-identity."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "concurrent-developer-login-leaves-the-pool-with-exactly-one-identity"
GROUP = 'concurrency'
SERVICES = ['cognito-identity']

N_RACERS = 8


def _list_identities(ci, pool_id):
    """Every identity in the pool, paginated. The pool is fresh, but ListIdentities caps
    MaxResults at 60 and the assertion below is a set difference, so the loop is not optional."""
    ids = set()
    next_token = None
    pages = 0
    while True:
        kwargs = {"IdentityPoolId": pool_id, "MaxResults": 60}
        if next_token:
            kwargs["NextToken"] = next_token
        resp = ci.list_identities(**kwargs)
        ids.update(i["IdentityId"] for i in resp.get("Identities", []))
        next_token = resp.get("NextToken")
        pages += 1
        if not next_token or pages > 50:
            return ids


def _settled_identities(ci, pool_id, baseline, timeout_s=90.0, interval_s=5.0):
    """The pool's identity set once two consecutive listings agree and include a new identity.
    ListIdentities is eventually consistent after a burst of creates."""
    deadline = time.time() + timeout_s
    previous = None
    while time.time() < deadline:
        current = _list_identities(ci, pool_id)
        if current - baseline and current == previous:
            return current
        previous = current
        time.sleep(interval_s)
    raise AssertionError(
        f"identity listing never settled within {timeout_s}s: last two readings were "
        f"{sorted(previous or [])!r} and {sorted(_list_identities(ci, pool_id))!r}"
    )


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Eight concurrent GetOpenIdTokenForDeveloperIdentity calls for one new developer user id all
    return the same IdentityId and leave the pool with exactly one new identity, that one.
    """
    ci = ctx.client("cognito-identity")
    developer_provider = ctx.unique_name("sim2real-behav-race-dev-")
    pool_id = ci.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real_behav_race_").replace("-", "_"),
        AllowUnauthenticatedIdentities=False,
        DeveloperProviderName=developer_provider,
        IdentityPoolTags={"sim2real": CHECK},
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))

    baseline = _list_identities(ci, pool_id)
    developer_user_id = ctx.unique_name("sim2real-behav-racer-")

    def _register():
        resp = ci.get_open_id_token_for_developer_identity(
            IdentityPoolId=pool_id, Logins={developer_provider: developer_user_id}
        )
        return resp["IdentityId"], resp["Token"]

    with ThreadPoolExecutor(max_workers=N_RACERS) as pool:
        futures = [pool.submit(_register) for _ in range(N_RACERS)]
        outcomes = []
        errors = []
        for f in futures:
            try:
                outcomes.append(f.result())
            except Exception as exc:  # noqa: BLE001 — reported in the assertion below
                errors.append(repr(exc))

    returned_ids = [identity_id for identity_id, _ in outcomes]
    tokens = [token for _, token in outcomes]
    assert len(returned_ids) == N_RACERS, (
        f"only {len(returned_ids)!r} of {N_RACERS} concurrent logins returned an identity; "
        f"errors: {errors!r}"
    )
    assert len(set(returned_ids)) == 1, (
        f"concurrent logins for one developer user produced {len(set(returned_ids))!r} distinct "
        f"identity ids: {sorted(set(returned_ids))!r}"
    )
    assert all(token and token.count(".") == 2 for token in tokens), (
        f"a returned token was not a three-part JWS: {[t[:12] for t in tokens]!r}"
    )

    # Matching ids alone would also pass if one identity were minted per caller and seven orphaned.
    settled = _settled_identities(ci, pool_id, baseline)
    new_ids = settled - baseline
    assert len(new_ids) == 1, (
        f"expected the pool to gain exactly 1 identity, it gained {sorted(new_ids)!r}"
    )
    assert new_ids == set(returned_ids), (
        f"the pool gained {sorted(new_ids)!r} but the callers were told {sorted(set(returned_ids))!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
