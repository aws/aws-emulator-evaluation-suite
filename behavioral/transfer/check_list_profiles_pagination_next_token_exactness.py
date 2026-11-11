"""list-profiles-pagination-next-token-exactness."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-profiles-pagination-next-token-exactness"
GROUP = 'error-semantics'
SERVICES = ['transfer']

# smithy MaxResults is range 1..1000; smithy NextToken is length 1..6144 with NO pattern, so a
# garbage token is a server-side rejection (it reaches the service) rather than a client-side one.
_MAX_PAGES = 200
_GARBAGE_TOKEN = 'sim2real-behav-not-a-real-next-token'


def _err(fn):
    """(code, message) of the ClientError fn raises; a call that succeeds fails the check."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get('Error', {})
        return err.get('Code'), err.get('Message')
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListProfiles honours MaxResults, ends by omitting NextToken, never repeats an item or token,
    and refuses a forged NextToken with InvalidNextTokenException rather than restarting at page 1.
    """
    tf = ctx.client('transfer')

    mine = set()
    for _ in range(3):
        pid = tf.create_profile(
            As2Id=ctx.unique_name('sim2real-behav-page-'), ProfileType='LOCAL',
            Tags=[{'Key': 'sim2real', 'Value': 'behavioral'}])['ProfileId']
        ctx.on_cleanup(lambda _p=pid: tf.delete_profile(ProfileId=_p))
        mine.add(pid)

    # Other profiles may exist and pages may legally be short, so no exact total, page count,
    # token format or ordering (ListProfiles promises none) is asserted.
    max_results = 1
    seen: list[str] = []
    token = None
    pages = 0
    terminal = None
    tokens_used = []
    while True:
        kwargs = {'MaxResults': max_results, 'ProfileType': 'LOCAL'}
        if token is not None:
            kwargs['NextToken'] = token
        page = tf.list_profiles(**kwargs)
        pages += 1

        got = page['Profiles']
        assert len(got) <= max_results, (
            f"page {pages} returned {len(got)} profiles for MaxResults={max_results}; "
            f"MaxResults was ignored"
        )
        seen.extend(p['ProfileId'] for p in got)
        for p in got:
            # ListedProfile is a projection; ProfileType must reflect the server-side filter.
            assert p['ProfileType'] == 'LOCAL', (
                f"ProfileType=LOCAL filter returned a {p['ProfileType']!r} profile: {p}"
            )

        nxt = page.get('NextToken')
        if nxt is None:
            terminal = page
            break
        assert isinstance(nxt, str) and nxt, (
            f"page {pages} returned a present-but-empty NextToken {nxt!r}; a terminal page must "
            f"OMIT the key entirely, not return an empty string"
        )
        assert nxt not in tokens_used, (
            f"page {pages} returned a NextToken already used ({nxt!r}); pagination is not "
            f"making progress and a correct client would loop forever"
        )
        tokens_used.append(nxt)
        token = nxt
        assert pages < _MAX_PAGES, f"ListProfiles did not terminate within {_MAX_PAGES} pages"

    # No item may be observed twice across pages, and every profile created above must appear.
    assert len(seen) == len(set(seen)), (
        f"pagination returned duplicate ProfileIds: "
        f"{sorted({p for p in seen if seen.count(p) > 1})}"
    )
    missing = mine - set(seen)
    assert not missing, f"paginated ListProfiles never returned {sorted(missing)}"

    # Termination is signalled by ABSENCE of the key, asserted explicitly because 'NextToken': ''
    # and 'NextToken': None are the two shapes emulators emit instead.
    assert 'NextToken' not in terminal, (
        f"the terminal ListProfiles page must omit NextToken, got {terminal.get('NextToken')!r}"
    )
    assert pages >= 2, (
        f"MaxResults=1 with {len(mine)} profiles present must require multiple pages; the "
        f"service returned everything in {pages} page(s)"
    )

    # A forged continuation token must be REFUSED, not silently treated as page 1.
    code, msg = _err(lambda: tf.list_profiles(NextToken=_GARBAGE_TOKEN))
    assert code == 'InvalidNextTokenException', (
        f"a forged NextToken must be rejected with InvalidNextTokenException (a modeled error on "
        f"every transfer List* operation), got {code!r}: {msg!r}"
    )
    assert msg == 'Invalid nextToken', f"unexpected forged-token diagnostic {msg!r}"

    # Control: the unpaginated call still works, so the refusal above is token validation and
    # not a broken listing.
    control = {p['ProfileId'] for p in tf.list_profiles(MaxResults=1000)['Profiles']}
    assert mine <= control, (
        f"unpaginated ListProfiles(MaxResults=1000) must still return every created profile "
        f"{sorted(mine)}; got {sorted(control)} (the NextToken rejection above would otherwise "
        f"be indistinguishable from a broken listing)"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
