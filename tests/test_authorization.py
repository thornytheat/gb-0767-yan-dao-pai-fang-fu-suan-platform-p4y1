from copy import deepcopy
from decimal import Decimal
from hashlib import sha256

import pytest

from app.archive.manifest import canonical
from app.archive.scope import (authorization_id, build_authorization, issue_authorization,
                               verify_authorization)
from app.errors import InputError
from app.monitor.hours import aggregate
from app.monitor.modes import mode_windows
from app.monitor.oxygen import correct
from app.monitor.reconcile import compare
from app.monitor.reports import index_reports
from app.monitor.revision import choose
from app.monitor.schema import Window
from app.monitor.validity import minute_evidence


@pytest.fixture
def granted(client):
    run_id = client.post('/api/runs', json={'sample': 'dirty'}).json['run_id']
    response = client.post(f'/api/authorizations/{run_id}', json={'hour': '2026-11-14T00:00Z'})
    return client, run_id, response


def test_first_issue_creates_one_authorization(granted):
    client, run_id, response = granted
    assert response.status_code == 201
    body = response.json
    assert body['reused'] is False and body['hour'] == '2026-11-14T00:00:00+00:00'
    assert body['authorization_id'] == authorization_id(run_id, body['hour'])

def test_retry_within_same_authorization_adds_no_sheet(granted):
    client, run_id, first = granted
    first_id = first.json['authorization_id']
    # 不同时区写法指向同一 UTC 小时，仍属同一次授权
    second = client.post(f'/api/authorizations/{run_id}', json={'hour': '2026-11-14T08:00+08:00'})
    assert (second.status_code, second.json['reused'], second.json['authorization_id']) == (200, True, first_id)
    third = client.post(f'/api/authorizations/{run_id}', json={'hour': '2026-11-14T00:00Z'})
    assert third.json['reused'] is True
    documents = client.get('/api/runs').json  # 留档仍只有一个批次
    assert len(documents['runs']) == 1


def test_distinct_hours_get_distinct_sheets(granted):
    client, run_id, _ = granted
    other = client.post(f'/api/authorizations/{run_id}', json={'hour': '2026-11-14T01:00Z'})
    assert other.status_code == 201 and other.json['reused'] is False
    assert other.json['authorization_id'] != granted[2].json['authorization_id']


def test_download_contract_and_digest(granted):
    client, run_id, issue = granted
    auth_id = issue.json['authorization_id']
    response = client.get(f'/api/authorizations/{run_id}/{auth_id}')
    assert response.status_code == 200
    assert response.headers['Content-Disposition'].startswith('attachment; filename="auth-')
    certificate = response.json
    assert certificate['certificate'] == '授权小时证据单'
    body = {key: value for key, value in certificate.items() if key != 'sha256'}
    assert certificate['sha256'] == sha256(canonical(body).encode()).hexdigest()
    assert verify_authorization(certificate) is True


def test_scoped_sheet_never_contains_full_originals(granted):
    client, run_id, issue = granted
    certificate = client.get(f"/api/authorizations/{run_id}/{issue.json['authorization_id']}").json
    assert 'originals' not in certificate
    blob = canonical(certificate)
    # 第二小时的分钟与窗外报送单据不得出现在授权证据中
    assert '2026-11-14T01:43' not in blob and 'R-803' not in blob
    # 授权小时的 60 个槽位齐全
    assert len(certificate['verdicts']['minutes']) == 60


def test_second_hour_sheet_is_scoped_to_its_own_evidence(client):
    run_id = client.post('/api/runs', json={'sample': 'dirty'}).json['run_id']
    response = client.post(f'/api/authorizations/{run_id}', json={'hour': '2026-11-14T01:00Z'})
    certificate = client.get(f"/api/authorizations/{run_id}/{response.json['authorization_id']}").json
    lines = {row['line'] for row in certificate['sources']['minutes']}
    # 小时内的迟补修订（108）与超截止版本（110）随单；上一小时的迟补件（109）不得漏入
    assert {108, 110}.issubset(lines) and 109 not in lines
    assert all(('T01:' in row['fields']['timestamp'] or 'T09:' in row['fields']['timestamp'])
               for row in certificate['sources']['minutes'])
    # 60 槽位仍齐全，仅 44 有效低于 45 门槛 → INSUFFICIENT，无公布浓度
    assert len(certificate['verdicts']['minutes']) == 60
    assert (certificate['verdicts']['hour']['status'], certificate['verdicts']['hour']['mg_nm3']) == (
        'INSUFFICIENT', None)
    assert [row['fields']['ticket'] for row in certificate['sources']['reports']] == ['R-802']
    # 超截止版本只作原件随单，不被裁决采信
    verdict = next(row for row in certificate['verdicts']['minutes']
                   if row['utc'] == '2026-11-14T01:43:00+00:00')
    assert (verdict['state'], [source['line'] for source in verdict['sources']]) == ('valid', [108])


def test_minute_sources_cover_conflicts_and_late_versions(granted):
    client, run_id, issue = granted
    response = client.get(f"/api/authorizations/{run_id}/{issue.json['authorization_id']}")
    certificate = response.json
    lines = {row['line'] for row in certificate['sources']['minutes']}
    # 第 17 槽位的同版冲突（原件 18、19 行）与 00:20 的迟补修订（109 行）都须随单
    assert {18, 19, 109}.issubset(lines)
    verdict = next(row for row in certificate['verdicts']['minutes'] if row['code'] == 'CONFLICT')
    assert [source['line'] for source in verdict['sources']] == [18, 19]


def test_reviewer_independently_recalculates_verdicts_and_hour(granted):
    client, run_id, issue = granted
    certificate = client.get(f"/api/authorizations/{run_id}/{issue.json['authorization_id']}").json
    window = Window.parse(certificate['scope']['window'])
    selected, conflicts, _ = choose(certificate['sources']['minutes'], window)
    for reading in selected.values():
        try:
            _, adjusted = correct(reading['fields'], window.reference)
            reading.update(reference_raw=adjusted, code='VALID')
        except ValueError as error:
            reading.update(code=str(error))
    intervals, _ = mode_windows(certificate['sources']['modes'], window)
    minutes = list(minute_evidence(window, selected, conflicts, intervals))
    for mine, theirs in zip(minutes, certificate['verdicts']['minutes']):
        assert (mine['state'], mine['code']) == (theirs['state'], theirs['code'])
        assert [s['line'] for s in mine['sources']] == [s['line'] for s in theirs['sources']]
    hour = aggregate(minutes, window)[0]
    expected = certificate['verdicts']['hour']
    assert (hour['valid'], hour['exempt'], hour['missing'], hour['mg_nm3']) == (
        expected['valid'], expected['exempt'], expected['missing'], expected['mg_nm3'])
    assert hour['mg_nm3'] == '30.50'
    reconciled, _ = compare([hour], certificate['sources']['reports'], window)
    assert (reconciled[0]['code'], reconciled[0]['difference_mg_nm3']) == ('DEVIATION', '0.75')


def test_cross_hour_mode_is_carried_whole_not_truncated(client):
    window = ('{"stack":"S-1","start":"2026-11-14T00:00Z","end":"2026-11-14T02:00Z",'
              '"cutoff":"2026-11-14T03:00Z","reference":"10","threshold":45,"tolerance":"0.50"}')
    minutes = 'stack,timestamp,value,unit,basis,moisture,oxygen,status,revision,received\n' + ''.join(
        f"S-1,2026-11-14T{h:02d}:{m:02d}Z,30,mg/Nm3,dry,-,10,OK,1,2026-11-14T{h:02d}:{m:02d}:30Z\n"
        for h in (0, 1) for m in range(60))
    modes = ('stack,start,end,mode\n'
             'S-1,2026-11-14T00:55Z,2026-11-14T01:05Z,SHUTDOWN\n')
    reports = ('stack,hour,value,ticket\n'
               'S-1,2026-11-14T00:00Z,30,R1\nS-1,2026-11-14T01:00Z,30,R2\n')
    run_id = client.post('/api/runs', json={'files': {'window': window, 'minutes': minutes,
                                                       'modes': modes, 'reports': reports}}).json['run_id']
    response = client.post(f'/api/authorizations/{run_id}', json={'hour': '2026-11-14T01:00Z'})
    certificate = client.get(f"/api/authorizations/{run_id}/{response.json['authorization_id']}").json
    carried = certificate['sources']['modes']
    assert len(carried) == 1
    assert (carried[0]['fields']['start'], carried[0]['fields']['end']) == (
        '2026-11-14T00:55Z', '2026-11-14T01:05Z')
    # 复核员仅凭整段工况即可复算边界 5 个免计分钟
    scoped_window = Window.parse(certificate['scope']['window'])
    selected, conflicts, _ = choose(certificate['sources']['minutes'], scoped_window)
    for reading in selected.values():
        reading.update(reference_raw=Decimal('30'), code='VALID')
    intervals, _ = mode_windows(carried, scoped_window)
    hour = aggregate(list(minute_evidence(scoped_window, selected, conflicts, intervals)), scoped_window)[0]
    assert (hour['exempt'], hour['valid']) == (5, 55)
    assert all('T01:' in row['fields']['timestamp'] for row in certificate['sources']['minutes'])


def test_invalid_hours_rejected(granted):
    client, run_id, _ = granted
    outside = client.post(f'/api/authorizations/{run_id}', json={'hour': '2026-11-14T03:00Z'})
    assert (outside.status_code, outside.json['code']) == (404, 'AUTH_HOUR_UNKNOWN')
    half = client.post(f'/api/authorizations/{run_id}', json={'hour': '2026-11-14T00:30Z'})
    assert (half.status_code, half.json['code']) == (404, 'AUTH_HOUR_UNKNOWN')
    bad = client.post(f'/api/authorizations/{run_id}', json={'hour': 'noon'})
    assert (bad.status_code, bad.json['code']) == (422, 'AUTH_HOUR_BAD')
    missing = client.post('/api/authorizations/unknown-run', json={'hour': '2026-11-14T00:00Z'})
    assert (missing.status_code, missing.json['code']) == (404, 'RUN_UNKNOWN')


def test_unknown_and_cross_run_authorization_404(client, granted):
    _, run_id, issue = granted
    assert client.get(f'/api/authorizations/{run_id}/nope').status_code == 404
    other_run = client.post('/api/runs', json={'sample': 'clean'}).json['run_id']
    response = client.get(f"/api/authorizations/{other_run}/{issue.json['authorization_id']}")
    assert response.status_code == 404


def test_tampered_scoped_sheet_fails_verification(granted):
    client, run_id, issue = granted
    certificate = client.get(f"/api/authorizations/{run_id}/{issue.json['authorization_id']}").json
    tampered = deepcopy(certificate)
    tampered['verdicts']['hour']['valid'] += 1
    with pytest.raises(InputError) as failure:
        verify_authorization(tampered)
    assert failure.value.code == 'EVIDENCE_UNBALANCED'
    tampered = deepcopy(certificate)
    tampered['sha256'] = '0' * 64
    with pytest.raises(InputError) as failure:
        verify_authorization(tampered)
    assert failure.value.code == 'AUTH_DIGEST_MISMATCH'


def test_store_retry_is_idempotent_after_restart(tmp_path):
    from app.archive.store import Archive
    from app.main import create_app

    db_path = tmp_path / 'auth.sqlite'
    run_id = create_app(db_path).test_client().post('/api/runs', json={'sample': 'dirty'}).json['run_id']
    # 重新打开库模拟服务重启，授权台账仍须持久且重试不新增
    store = Archive(db_path)
    first, reused_first = issue_authorization(store, run_id, '2026-11-14T00:00Z')
    second, reused_second = issue_authorization(store, run_id, '2026-11-14T00:00Z')
    assert (reused_first, reused_second) == (False, True)
    assert first['authorization_id'] == second['authorization_id']
    assert len(store.authorizations(run_id)) == 1


def test_build_requires_balanced_hour(client):
    run_id = client.post('/api/runs', json={'sample': 'dirty'}).json['run_id']
    packet = client.application.extensions['monitor_archive'].require(run_id)
    # 把一个缺证分钟改成有效，破坏 60 槽位的状态守恒
    target = next(row for row in packet['results']['validity']['rows'] if row['state'] == 'missing')
    broken = deepcopy(packet)
    broken_row = next(row for row in broken['results']['validity']['rows'] if row['utc'] == target['utc'])
    broken_row['state'], broken_row['code'] = 'valid', 'VALID'
    with pytest.raises(InputError) as failure:
        build_authorization(broken, '2026-11-14T00:00:00+00:00')
    assert failure.value.code == 'EVIDENCE_UNBALANCED'


def test_evidence_page_lists_authorizations(client):
    run_id = client.post('/api/runs', json={'sample': 'dirty'}).json['run_id']
    client.post(f'/api/authorizations/{run_id}', json={'hour': '2026-11-14T00:00Z'})
    page = client.get(f'/monitor/evidence?run={run_id}').get_data(as_text=True)
    assert '授权小时证据单' in page and 'auth-form' in page
    assert f'/api/authorizations/{run_id}/' in page
    # 内部完整证据入口保留
    assert f'/api/export/{run_id}' in page
