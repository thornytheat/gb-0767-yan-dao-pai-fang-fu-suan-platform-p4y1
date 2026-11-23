"""按授权小时裁剪监测证据。

外部复核员一次只获准查阅一个整点小时。裁剪后的证据单只保留该小时 60 个分钟
槽位的裁决与原件行；横跨整点的工况记录整条保留（不在小时边界截断），否则免计
分钟会因缺证被误判。完整原件文本仍只留在内部留档中，不进入本证据单。
"""
from hashlib import sha256

from app.archive.manifest import canonical
from app.errors import InputError
from app.monitor.clock import HOUR, local, minute
from app.monitor.schema import HEADERS
from app.monitor.source import intake

AUTH_VERSION = 'AUTH-1.0'


def authorization_id(run_id, hour):
    return sha256(canonical(['AUTH', run_id, hour]).encode()).hexdigest()


def _window_hours(window):
    count = int((window.end - window.start) / HOUR)
    return [window.start + index * HOUR for index in range(count)]


def _within(value, start, end):
    return start <= value < end


def _minute_rows(ledger, hour_start):
    """保留时间戳落在授权小时内的分钟原件行（含同版冲突、被替代与迟补版本）。"""
    hour_end = hour_start + HOUR
    rows = []
    for row in ledger:
        try:
            when = minute(row['fields']['timestamp'])
        except ValueError:
            continue
        if _within(when, hour_start, hour_end):
            rows.append(row)
    return rows


def _mode_rows(ledger, hour_start):
    """整条保留与授权小时相交的有效工况原件，横跨整点也不截断。

    区间非法（倒置、坏模式等）的行无法界定相交关系，它们已进入隔离表，
    不作为免计依据随单。
    """
    hour_end = hour_start + HOUR
    rows = []
    for row in ledger:
        fields = row['fields']
        try:
            start, end = minute(fields['start']), minute(fields['end'])
        except ValueError:
            continue
        if end <= start:
            continue
        if start < hour_end and end > hour_start:
            rows.append(row)
    return rows


def _report_rows(ledger, hour_start):
    rows = []
    for row in ledger:
        try:
            when = minute(row['fields']['hour'])
        except ValueError:
            continue
        if when == hour_start:
            rows.append(row)
    return rows


def _scoped_window(window, hour_start):
    # 只暴露授权小时的时窗边界；折算参比氧、门槛、容差与收件截止原样保留。
    return {'stack': window.stack, 'start': hour_start.isoformat(),
            'end': (hour_start + HOUR).isoformat(), 'cutoff': window.cutoff.isoformat(),
            'reference': str(window.reference), 'threshold': window.threshold,
            'tolerance': str(window.tolerance)}


def build_authorization(packet, hour_text):
    run_id = packet['manifest']['run_id']
    window, ledgers = intake(packet['originals'])
    try:
        hour_start = minute(hour_text)
    except (TypeError, ValueError):
        raise InputError('AUTH_HOUR_BAD', '授权小时须为带偏移的整点时刻', 422) from None
    if hour_start.minute or hour_start not in _window_hours(window):
        raise InputError('AUTH_HOUR_UNKNOWN', '授权小时不在监测窗口内', 404)

    sources = {name: [] for name in HEADERS}
    sources['minutes'] = _minute_rows(ledgers['minutes'][0], hour_start)
    sources['modes'] = _mode_rows(ledgers['modes'][0], hour_start)
    sources['reports'] = _report_rows(ledgers['reports'][0], hour_start)

    hour_iso = hour_start.isoformat()
    verdicts = [row for row in packet['results']['validity']['rows'] if row['utc'][:13] == hour_iso[:13]]
    hour_row = next((row for row in packet['results']['hours']['rows'] if row['hour'] == hour_iso), None)
    report_row = next((row for row in packet['results']['reports']['rows'] if row['hour'] == hour_iso), None)
    if hour_row is None or report_row is None:
        raise InputError('EVIDENCE_UNBALANCED', '授权小时汇总或对账缺失', 409)
    if len(verdicts) != 60 or hour_row['scheduled'] != 60:
        raise InputError('EVIDENCE_UNBALANCED', '授权小时分钟裁决不完整', 409)
    # 逐状态与留档小时汇总勾稽，状态被篡改时三种计数无法同时对上
    state_counts = {state: sum(1 for row in verdicts if row['state'] == state)
                    for state in ('valid', 'exempt', 'missing')}
    if any(state_counts[state] != hour_row[state] for state in state_counts) or sum(state_counts.values()) != 60:
        raise InputError('EVIDENCE_UNBALANCED', '授权小时分钟勾稽尚未平衡', 409)

    auth_id = authorization_id(run_id, hour_iso)
    body = {
        'certificate': '授权小时证据单', 'authorization_version': AUTH_VERSION,
        'authorization_id': auth_id, 'run_id': run_id, 'rule': packet['manifest']['rule'],
        'scope': {'stack': window.stack, 'hour': hour_iso, 'hour_local': local(hour_start),
                  'window': _scoped_window(window, hour_start)},
        'sources': sources,
        'verdicts': {'minutes': verdicts, 'hour': hour_row, 'report': report_row,
                     'isolated_modes': packet['results']['validity']['isolated_modes']},
        'checks': {'minute_balance': 0, 'scheduled': 60,
                   'source_sha256': {key: sha256(canonical(rows).encode()).hexdigest()
                                     for key, rows in sources.items()}},
    }
    return body | {'sha256': sha256(canonical(body).encode()).hexdigest()}


def issue_authorization(store, run_id, hour_text):
    # 先解析授权小时，非法时刻直接拒绝；同一 (run, 小时) 重试复用既有证据单。
    try:
        hour_iso = minute(hour_text).isoformat()
    except (TypeError, ValueError):
        raise InputError('AUTH_HOUR_BAD', '授权小时须为带偏移的整点时刻', 422) from None
    packet = store.require(run_id)
    existing = store.find_authorization(run_id, hour_iso)
    if existing is not None:
        return existing, True
    certificate = build_authorization(packet, hour_iso)
    stored, inserted = store.commit_authorization(certificate['authorization_id'], run_id, certificate)
    # 并发下唯一索引可能让本次写入落空并返回先到的证据单：写入落空即按复用处理，不产生第二份
    return stored, not inserted


def verify_authorization(certificate):
    """供复核员独立校验：分钟勾稽、小时汇总自洽与内容摘要。"""
    verdicts = certificate['verdicts']['minutes']
    hour = certificate['verdicts']['hour']
    if len(verdicts) != 60 or hour['scheduled'] != 60:
        raise InputError('EVIDENCE_UNBALANCED', '授权小时分钟裁决不完整', 409)
    counts = {state: sum(1 for row in verdicts if row['state'] == state)
              for state in ('valid', 'exempt', 'missing')}
    if any(counts[state] != hour[state] for state in counts) or sum(counts.values()) != 60:
        raise InputError('EVIDENCE_UNBALANCED', '分钟裁决与小时汇总勾稽不符', 409)
    if certificate['checks']['minute_balance'] != 0:
        raise InputError('EVIDENCE_UNBALANCED', '授权小时分钟勾稽尚未平衡', 409)
    body = {key: value for key, value in certificate.items() if key != 'sha256'}
    if certificate.get('sha256') != sha256(canonical(body).encode()).hexdigest():
        raise InputError('AUTH_DIGEST_MISMATCH', '授权证据摘要不符', 409)
    return True
