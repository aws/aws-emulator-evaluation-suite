"""repository-policy-self-lockout-with-force-actually-blocks-set-repository-policy."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "repository-policy-self-lockout-with-force-actually-blocks-set-repository-policy"
GROUP = "repository-policy"
SERVICES = ["ecr-public"]

_LOCK_BUDGET_S = 120.0
_LOCK_INTERVAL_S = 3.0


def _error(fn, *, what: str) -> dict:
    """Call fn and return the ClientError's Error (Code and Message); a success raises."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"{what} succeeded; it must have been refused")


def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    """Bounded retry that raises on exhaustion rather than returning its last value."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} was not observed within {timeout_s}s; last read was {last!r}"
    )


def _ecr_public(ctx):
    """ECR Public's control plane is served only from us-east-1; elsewhere every operation answers
    UnsupportedCommandException, so the client is region-pinned."""
    return ctx.client("ecr-public", region="us-east-1")


def _create_repository(ctx, ecr, name=None, **kwargs):
    name = name or ctx.unique_name("sim2real-behav-ecrpub-lock-")
    resp = ecr.create_repository(repositoryName=name, **kwargs)
    # Teardown order matters: the policy is dropped first so the repository is never left holding a
    # self-locking document, then the repository goes.
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=name, force=True))
    ctx.on_cleanup(lambda: ecr.delete_repository_policy(repositoryName=name))
    return name, resp


def _benign_policy(account_id: str, sid: str) -> str:
    """An Allow-only policy that grants an action the account already has. It changes nothing, so
    storing it is a pure test of whether SetRepositoryPolicy is reachable at all."""
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": sid,
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                    "Action": ["ecr-public:BatchCheckLayerAvailability"],
                }
            ],
        },
        separators=(",", ":"),
    )


def _self_lock_policy(account_id: str) -> str:
    """Deny exactly ONE action -- SetRepositoryPolicy -- for the account root. Nothing else is
    denied, so DeleteRepositoryPolicy (the escape hatch) and DeleteRepository (the teardown) stay
    reachable. That is the single broken thing, and it is restorable."""
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "sim2realDenySetRepositoryPolicy",
                    "Effect": "Deny",
                    "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                    "Action": ["ecr-public:SetRepositoryPolicy"],
                }
            ],
        },
        separators=(",", ":"),
    )


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A forced self-locking repository policy is not just stored -- it is ENFORCED: the next
    SetRepositoryPolicy is denied, the stored document is unchanged, and dropping the policy
    restores the identical call."""
    ecr = _ecr_public(ctx)
    identity = ctx.client("sts").get_caller_identity()
    account_id = identity["Account"]
    # The denial message names the calling principal and the repository; both are read here so the
    # expected text holds for whichever identity runs the check.
    caller_arn = identity["Arn"]
    name, created = _create_repository(ctx, ecr)
    repo_arn = created["repository"]["repositoryArn"]

    benign = _benign_policy(account_id, "sim2realBaseline")
    lock = _self_lock_policy(account_id)

    # --- BEAT 1: positive control. SetRepositoryPolicy works on this repository, now. ------------
    first = ecr.set_repository_policy(repositoryName=name, policyText=benign)
    assert first["repositoryName"] == name, (
        f"SetRepositoryPolicy echoed repositoryName {first.get('repositoryName')!r}, "
        f"expected {name!r}"
    )
    stored_benign = ecr.get_repository_policy(repositoryName=name)["policyText"]
    assert json.loads(stored_benign)["Statement"][0]["Sid"] == "sim2realBaseline", (
        f"GetRepositoryPolicy returned {stored_benign!r} after storing the baseline policy"
    )

    # --- the SERVICE ITSELF classifies the lock policy as a lockout ----------------------
    # This is the target's own judgement, not this check's opinion, and it is what makes the
    # enforcement assertion below non-trivial: the service says this policy would lock us out.
    unforced = _error(
        lambda: ecr.set_repository_policy(repositoryName=name, policyText=lock),
        what="SetRepositoryPolicy storing a self-locking policy WITHOUT force",
    )
    assert unforced["Code"] == "InvalidParameterException", (
        f"the unforced self-locking policy was refused {unforced!r}; expected "
        f"InvalidParameterException, the only input-shaped error SetRepositoryPolicy models"
    )
    expected = (
        "You are about to set a repository policy that will prevent you from setting another one "
        "in the future. Use the force parameter to override this exception."
    )
    assert unforced["Message"] == expected, f"{unforced['Message']!r} != {expected!r}"
    # ...and the refusal changed nothing.
    unchanged = ecr.get_repository_policy(repositoryName=name)["policyText"]
    assert unchanged == stored_benign, (
        f"the refused unforced call altered the stored policy: {unchanged!r} != {stored_benign!r}"
    )

    # --- BEAT 2: break exactly one thing -- store the lock, forced ------------------------------
    forced = ecr.set_repository_policy(repositoryName=name, policyText=lock, force=True)
    assert forced["repositoryName"] == name, (
        f"the forced SetRepositoryPolicy echoed {forced.get('repositoryName')!r}, "
        f"expected {name!r}"
    )
    # An independent read confirms it landed verbatim.
    stored_lock_doc = json.loads(ecr.get_repository_policy(repositoryName=name)["policyText"])
    lock_statement = stored_lock_doc["Statement"][0]
    assert lock_statement["Effect"] == "Deny", (
        f"the stored policy's effect is {lock_statement.get('Effect')!r}, expected 'Deny': "
        f"{stored_lock_doc!r}"
    )
    assert lock_statement["Sid"] == "sim2realDenySetRepositoryPolicy", (
        f"the stored statement is {lock_statement!r}, not the lock statement that was sent"
    )
    # AWS normalizes a single-element Action array to a scalar string on read-back, so the
    # meaningful check is the action set, not the JSON container shape.
    stored_action = lock_statement["Action"]
    if isinstance(stored_action, str):
        stored_action = [stored_action]
    assert stored_action == ["ecr-public:SetRepositoryPolicy"], (
        f"the stored Action is {lock_statement.get('Action')!r}; the lock must name exactly "
        f"['ecr-public:SetRepositoryPolicy'] so DeleteRepositoryPolicy stays reachable"
    )

    # --- BEAT 3: THE POINT. The stored lock actually blocks the next SetRepositoryPolicy. --------
    # Polled, because a resource policy may take a moment to become effective, and the poll RAISES
    # on exhaustion: a target that stores the Deny and never enforces it fails HERE, which is
    # exactly the "config field stored but never proven to do anything" failure mode.
    second_benign = _benign_policy(account_id, "sim2realAfterLock")
    denied = _poll_until(
        lambda: _attempt(ecr, name, second_benign),
        lambda outcome: outcome["refused"],
        timeout_s=_LOCK_BUDGET_S,
        interval_s=_LOCK_INTERVAL_S,
        description=(
            f"SetRepositoryPolicy on {name} being refused after a forced self-locking Deny was "
            f"stored -- a stored Deny that never binds is the defect this check exists to catch"
        ),
    )["error"]
    assert denied["Code"] == "AccessDeniedException", (
        f"the locked-out SetRepositoryPolicy was refused {denied!r}, expected "
        f"AccessDeniedException -- the code must separate 'the repository policy denied this "
        f"action' from a malformed request or a missing repository"
    )
    expected = (
        f"User: {caller_arn} is not authorized to perform: ecr-public:SetRepositoryPolicy on "
        f"resource: {repo_arn} with an explicit deny in a resource-based policy"
    )
    assert denied["Message"] == expected, f"{denied['Message']!r} != {expected!r}"

    # --- BEAT 4: the effect is ABSENT via an independent read ------------------------------------
    still_locked = json.loads(ecr.get_repository_policy(repositoryName=name)["policyText"])
    assert still_locked["Statement"][0]["Sid"] == "sim2realDenySetRepositoryPolicy", (
        f"the denied SetRepositoryPolicy landed anyway: the stored policy is now {still_locked!r}"
    )
    assert "sim2realAfterLock" not in json.dumps(still_locked), (
        f"the denied policy's Sid is present in the stored document: {still_locked!r}"
    )

    # --- BEAT 5: RESTORE. Drop the policy -- the Deny does not name DeleteRepositoryPolicy. ------
    ecr.delete_repository_policy(repositoryName=name)
    gone = _error(
        lambda: ecr.get_repository_policy(repositoryName=name),
        what=f"GetRepositoryPolicy on {name} after DeleteRepositoryPolicy",
    )
    assert gone["Code"] == "RepositoryPolicyNotFoundException", (
        f"after DeleteRepositoryPolicy, GetRepositoryPolicy answered {gone!r}, expected "
        f"RepositoryPolicyNotFoundException"
    )
    expected = (
        f"Repository policy does not exist for the repository with name '{name}' in the "
        f"registry with id '{ctx.account}'"
    )
    assert gone["Message"] == expected, f"{gone['Message']!r} != {expected!r}"

    # --- BEAT 6: the IDENTICAL call that was denied now succeeds ---------------------------------
    restored = ecr.set_repository_policy(repositoryName=name, policyText=second_benign)
    assert restored["repositoryName"] == name, (
        f"the restored SetRepositoryPolicy echoed {restored.get('repositoryName')!r}, "
        f"expected {name!r}"
    )
    final_doc = json.loads(ecr.get_repository_policy(repositoryName=name)["policyText"])
    assert final_doc["Statement"][0]["Sid"] == "sim2realAfterLock", (
        f"after the restore, the stored policy is {final_doc!r}, not the previously denied "
        f"document"
    )
    assert final_doc["Statement"][0]["Effect"] == "Allow", (
        f"the restored statement's effect is {final_doc['Statement'][0].get('Effect')!r}, "
        f"expected 'Allow'"
    )


def _attempt(ecr, name, policy_text):
    """Attempt SetRepositoryPolicy once: ``{"refused": True, "error": ...}`` on a ClientError, or
    ``{"refused": False, "response": ...}`` on success, which the bounded poll keeps waiting past
    and RAISES on at exhaustion."""
    try:
        response = ecr.set_repository_policy(repositoryName=name, policyText=policy_text)
    except ClientError as exc:
        return {"refused": True, "error": exc.response["Error"]}
    return {"refused": False, "response": response}


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
