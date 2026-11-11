"""concurrent-template-create-exactly-one-body-renders."""
from __future__ import annotations

import concurrent.futures
import email

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-template-create-exactly-one-body-renders"
GROUP = 'concurrency'
SERVICES = ['sesv2']

_WORKERS = 5


def _mime(rendered: str):
    """Parse a TestRenderEmailTemplate result as the MIME message it actually is."""
    msg = email.message_from_string(rendered)
    assert msg.defects == [], f'the rendered template is not a well-formed MIME message: {msg.defects!r}'
    return msg


def _part_text(part) -> str:
    raw = part.get_payload(decode=True)
    assert raw is not None, f'part {part.get_content_type()!r} carries no decodable payload'
    return raw.decode(part.get_content_charset() or 'utf-8')


def _client_error(fn) -> ClientError:
    try:
        result = fn()
    except ClientError as exc:
        return exc
    raise AssertionError(f'the call was expected to be refused but it succeeded: {result!r}')


@tags("axis:happy-path", "concern:data-plane", "dp:api", "plane:data", "cap:c1")
def run(ctx) -> None:
    """Five concurrent CreateEmailTemplate calls on one name with different bodies yield exactly one
    winner, the rest refused for this template, and the render carries only the winner's body.
    """
    ses = ctx.client('sesv2')
    name = ctx.unique_name('sim2real-behav-tplrace-')
    bodies = {i: f'body-{i}' for i in range(_WORKERS)}

    def _cleanup(_n=name):
        try:
            ses.delete_email_template(TemplateName=_n)
        except ClientError as exc:
            # Only tolerated when no create won at all; every other code is a real cleanup failure.
            if exc.response['Error']['Code'] != 'NotFoundException':
                raise

    # Registered before the race: the winner is unknown, but the name is the whole handle.
    ctx.on_cleanup(_cleanup)

    # Clients are built before the executor starts: botocore client creation is not thread-safe.
    clients = [ctx.client('sesv2') for _ in range(_WORKERS)]

    def _create(idx):
        try:
            clients[idx].create_email_template(
                TemplateName=name,
                TemplateContent={
                    'Subject': f'subj-{idx}',
                    'Text': bodies[idx],
                    'Html': f'<p>{bodies[idx]}</p>',
                },
                Tags=[{'Key': 'sim2real', 'Value': CHECK}],
            )
            return idx, None
        except ClientError as exc:
            return idx, exc

    with concurrent.futures.ThreadPoolExecutor(max_workers=_WORKERS) as pool:
        outcomes = list(pool.map(_create, range(_WORKERS)))

    winners = [idx for idx, exc in outcomes if exc is None]
    losers = [(idx, exc) for idx, exc in outcomes if exc is not None]

    assert len(winners) == 1, (
        f'exactly one of {_WORKERS} simultaneous creates of the same template name may be accepted, got '
        f'{len(winners)} winners {winners!r}; losers reported '
        f'{[(i, e.response["Error"]) for i, e in losers]!r}'
    )
    assert len(losers) == _WORKERS - 1, (
        f'every create that did not win must be refused, got {len(losers)} refusals out of {_WORKERS}'
    )
    already_exists = f'Template {name} already exists for account id {ctx.account}'
    refusals = {
        'AlreadyExistsException': 'Template already exists',
        'BadRequestException': f'Template is already created with {name}/EMAIL',
    }
    for idx, exc in losers:
        code = exc.response['Error']['Code']
        message = exc.response['Error'].get('Message') or ''
        status = exc.response['ResponseMetadata']['HTTPStatusCode']
        assert status == 400, (
            f'loser {idx} must be refused as a client error, got HTTP {status!r}: '
            f'{exc.response["Error"]!r}'
        )
        # A loser racing the winner's commit gets BadRequestException; one arriving after it gets
        # AlreadyExistsException (no name for a tagged create). Either is timing-dependent; the two
        # are allowed so a throttle or quota refusal cannot pass.
        assert code in refusals and message == refusals[code], (
            f'loser {idx} must be refused because THIS template already exists -- a throttle or a quota '
            f'refusal would prove nothing about atomicity; got {exc.response["Error"]!r}'
        )

    winner = winners[0]
    msg = _mime(ses.test_render_email_template(TemplateName=name, TemplateData='{}')['RenderedTemplate'])
    parts = [_part_text(p) for p in msg.get_payload()]
    assert parts == [bodies[winner], f'<p>{bodies[winner]}</p>'], (
        f'the render must reproduce the winning create\'s body ({bodies[winner]!r}), got {parts!r}'
    )
    rendered_blob = ''.join(parts) + (msg['Subject'] or '')
    intruders = [bodies[i] for i in bodies if i != winner and bodies[i] in rendered_blob]
    assert intruders == [], (
        f'a losing create\'s body reached the store: {intruders!r} appear in the render {parts!r} / '
        f'subject {msg["Subject"]!r}'
    )
    assert ses.get_email_template(TemplateName=name)['TemplateContent']['Text'] == bodies[winner], (
        'the stored Text must be the winner\'s, got '
        f'{ses.get_email_template(TemplateName=name)["TemplateContent"]["Text"]!r}'
    )

    # Once the race is settled, a duplicate create is refused deterministically.
    serial = _client_error(lambda: ses.create_email_template(
        TemplateName=name, TemplateContent={'Subject': 'subj-late', 'Text': 'body-late'}))
    serial_error = (serial.response['Error']['Code'], serial.response['Error'].get('Message'))
    assert serial_error == ('AlreadyExistsException', already_exists), (
        'a duplicate create issued after the race has settled must be refused with AlreadyExistsException, '
        f'got {serial.response["Error"]!r}'
    )
    assert ses.get_email_template(TemplateName=name)['TemplateContent']['Text'] == bodies[winner], (
        'the late duplicate overwrote the stored body: '
        f'{ses.get_email_template(TemplateName=name)["TemplateContent"]!r}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
