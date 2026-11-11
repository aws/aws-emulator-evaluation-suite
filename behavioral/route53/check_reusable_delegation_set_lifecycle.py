"""reusable-delegation-set-lifecycle."""

from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "reusable-delegation-set-lifecycle"
GROUP = 'delegation-set'
SERVICES = ['route53']


def _caller_reference():
    return f"cr-{uuid.uuid4()}"


def _client_error(fn):
    """Call fn(); return its botocore Error (code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _delete_ignore_missing(r53, ds_id):
    try:
        r53.delete_reusable_delegation_set(Id=ds_id)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchDelegationSet":
            raise


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateReusableDelegationSet is visible via Get/List, and once deleted it no longer
    resolves through Get or List and a second delete on the same id also fails."""
    r53 = ctx.client("route53")
    resp = r53.create_reusable_delegation_set(CallerReference=_caller_reference())
    ds_id = resp["DelegationSet"]["Id"]
    ctx.on_cleanup(lambda i=ds_id: _delete_ignore_missing(r53, i))
    assert resp["DelegationSet"]["NameServers"], resp["DelegationSet"]

    got = r53.get_reusable_delegation_set(Id=ds_id)
    assert got["DelegationSet"]["Id"] == ds_id, got["DelegationSet"]

    listed = r53.list_reusable_delegation_sets()
    assert any(d["Id"] == ds_id for d in listed["DelegationSets"]), (ds_id, listed["DelegationSets"])

    r53.delete_reusable_delegation_set(Id=ds_id)

    # a mutation on the dead id also fails, not just a read
    expected_message = ds_id.rsplit("/", 1)[-1]
    dup_code, dup_message = _client_error(lambda: r53.delete_reusable_delegation_set(Id=ds_id))
    assert dup_code == "NoSuchDelegationSet", dup_code
    assert dup_message == expected_message, dup_message

    code, message = _client_error(lambda: r53.get_reusable_delegation_set(Id=ds_id))
    assert code == "NoSuchDelegationSet", code
    assert message == expected_message, message

    listed_after = r53.list_reusable_delegation_sets()
    assert not any(d["Id"] == ds_id for d in listed_after["DelegationSets"]), listed_after["DelegationSets"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
