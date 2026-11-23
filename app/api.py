from flask import Blueprint, current_app, jsonify, request

from app.archive.certificate import issue
from app.archive.run import archive_run
from app.archive.scope import issue_authorization
from app.errors import InputError
from app.monitor.inspection import STAGES, Inspection
from app.monitor.source import sample

api = Blueprint('api', __name__, url_prefix='/api')


def archive():
    return current_app.extensions['monitor_archive']


@api.get('/samples/<name>/<stage>')
def preview(name, stage):
    if stage not in STAGES:
        raise InputError('STAGE_UNKNOWN', '找不到监测工序', 404)
    return jsonify(getattr(Inspection(sample(name)), stage))


@api.post('/runs')
def create_run():
    packet, reused = archive_run(archive(), request.get_json(silent=True))
    return jsonify(run_id=packet['manifest']['run_id'], reused=reused, manifest=packet['manifest'],
                   totals=packet['results']['hours']['totals'], deviations=packet['results']['reports']['deviations'])


@api.get('/runs')
def runs():
    return jsonify(runs=archive().history())


@api.get('/runs/<run_id>/<stage>')
def snapshot(run_id, stage):
    if stage not in STAGES:
        raise InputError('STAGE_UNKNOWN', '找不到监测工序', 404)
    return jsonify(archive().require(run_id)['results'][stage])


@api.get('/export/<run_id>')
def export(run_id):
    response = jsonify(issue(archive().require(run_id)))
    response.headers['Content-Disposition'] = f'attachment; filename="monitor-{run_id}.json"'
    return response


@api.post('/authorizations/<run_id>')
def authorize(run_id):
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict) or not isinstance(payload.get('hour'), str):
        raise InputError('AUTH_HOUR_BAD', '请提供授权小时 hour')
    certificate, reused = issue_authorization(archive(), run_id, payload['hour'])
    response = jsonify(authorization_id=certificate['authorization_id'], reused=reused,
                       hour=certificate['scope']['hour'], sha256=certificate['sha256'])
    response.status_code = 200 if reused else 201
    return response


@api.get('/authorizations/<run_id>/<auth_id>')
def authorization_document(run_id, auth_id):
    certificate = archive().lookup_authorization(auth_id)
    if certificate is None or certificate['run_id'] != run_id:
        raise InputError('AUTH_UNKNOWN', '找不到授权小时证据单', 404)
    response = jsonify(certificate)
    response.headers['Content-Disposition'] = (
        f'attachment; filename="auth-{run_id[:12]}-{certificate["scope"]["hour"][11:13]}.json"')
    return response
