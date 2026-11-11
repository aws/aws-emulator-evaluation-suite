"""register-pull-time-update-exclusion-duplicate-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "register-pull-time-update-exclusion-duplicate-rejected"
GROUP = "overly-permissive"
SERVICES = ["ecr"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:ecr-pull-time-exclusions")
def run(ctx) -> None:
    """Registering a pull-time update exclusion twice is refused ExclusionAlreadyExistsException
    with the exact message and lists the principal once; after deregistering, it registers again,
    a second principal registers too, and each is listed once."""
    ecr = ctx.client("ecr")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    principal = f"arn:aws:iam::{account_id}:role/{ctx.unique_name('sim2real-ecr-excl-')}"
    other_principal = f"arn:aws:iam::{account_id}:role/{ctx.unique_name('sim2real-ecr-excl2-')}"

    first = ecr.register_pull_time_update_exclusion(principalArn=principal)
    ctx.on_cleanup(lambda: _deregister(ecr, principal))
    assert first["principalArn"] == principal, (
        f"expected principalArn {principal!r} echoed back from register, got "
        f"{first['principalArn']!r}"
    )

    code, message = _client_error(lambda: ecr.register_pull_time_update_exclusion(principalArn=principal))
    assert code == "ExclusionAlreadyExistsException", (
        f"expected ExclusionAlreadyExistsException registering {principal!r} a second time "
        f"while it is still registered, got {code!r}"
    )
    expected = (
        f"The pull time update exclusion for principal arn '{principal}' already exists in "
        f"registry with id '{account_id}'"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # effect absent: exactly one stored entry for this principal, not two
    entries = [e for e in _list_all_exclusions(ecr) if e == principal]
    assert len(entries) == 1, (
        f"expected exactly one stored exclusion for {principal!r} after the rejected "
        f"duplicate register, got {len(entries)}"
    )

    # restore: the rejection tracks live state, not the ARN permanently — deregister, then the
    # identical call must succeed again
    ecr.deregister_pull_time_update_exclusion(principalArn=principal)
    restored = ecr.register_pull_time_update_exclusion(principalArn=principal)
    assert restored["principalArn"] == principal, (
        f"expected re-registering {principal!r} to succeed once it was deregistered, got "
        f"{restored['principalArn']!r}"
    )

    # positive control: a different principal can still be registered
    second = ecr.register_pull_time_update_exclusion(principalArn=other_principal)
    ctx.on_cleanup(lambda: _deregister(ecr, other_principal))
    assert second["principalArn"] == other_principal, (
        f"expected principalArn {other_principal!r} echoed back from register, got "
        f"{second['principalArn']!r}"
    )

    # terminal: independent read at the destination, not either register call's own response
    final = _list_all_exclusions(ecr)
    assert final.count(principal) == 1, (
        f"expected {principal!r} to appear exactly once in the exclusion list after the "
        f"deregister/re-register restore, got {final.count(principal)}"
    )
    assert final.count(other_principal) == 1, (
        f"expected {other_principal!r} to appear exactly once in the exclusion list, got "
        f"{final.count(other_principal)}"
    )


def _client_error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected success
    raises, so an emulator that accepts what AWS refuses fails loudly instead of reading as a
    code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _list_all_exclusions(ecr):
    out = []
    token = None
    while True:
        kwargs = {"maxResults": 1000}
        if token:
            kwargs["nextToken"] = token
        resp = ecr.list_pull_time_update_exclusions(**kwargs)
        out.extend(resp.get("pullTimeUpdateExclusions", []))
        token = resp.get("nextToken")
        if not token:
            break
    return out


def _deregister(ecr, principal_arn):
    from botocore.exceptions import ClientError

    try:
        ecr.deregister_pull_time_update_exclusion(principalArn=principal_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ExclusionNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
