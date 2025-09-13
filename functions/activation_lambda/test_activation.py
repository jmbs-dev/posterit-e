import json
import pytest
from unittest.mock import Mock, patch

import app


# ---------------- Fixtures ----------------
@pytest.fixture
def context():
    c = Mock(); c.aws_request_id = "req"; return c

@pytest.fixture
def base_env():
    with patch.dict('os.environ', {
        'DYNAMODB_TABLE_NAME': 'tbl',
        'RELEASE_LAMBDA_ARN': 'rel-arn',
        'SCHEDULER_ROLE_ARN': 'sched-role'
    }):
        yield

@pytest.fixture
def get_event():
    return {"httpMethod": "GET", "pathParameters": {"secretId": "sec-1"}}

@pytest.fixture
def post_event_valid():
    return {"httpMethod": "POST", "body": json.dumps({"secretId": "sec-1", "clientHash": "H"})}

@pytest.fixture
def config_item():
    return {
        'saltCr': 'salt',
        'passwordHashCr': 'H',
        'processStatus': 'INITIAL',
        'titularAlertContact': 'owner@example.com',
        'gracePeriodSeconds': 100
    }



# ---------------- GET Salt Tests ----------------
@patch('app._get_secret_config', return_value={'saltCr': 'saltX'})
def test_get_salt_success(get_cfg, base_env, get_event):
    resp = app.get_salt_for_secret(get_event, 'tbl')
    assert resp['statusCode'] == 200
    assert 'saltX' in resp['body']

def test_get_salt_missing_id(base_env):
    resp = app.get_salt_for_secret({"httpMethod": "GET", "pathParameters": {}}, 'tbl')
    assert resp['statusCode'] == 400

@patch('app._get_secret_config', return_value=None)
def test_get_salt_not_found(_, base_env, get_event):
    resp = app.get_salt_for_secret(get_event, 'tbl')
    assert resp['statusCode'] == 401


# ---------------- Scheduling Helper ----------------
@patch('app.scheduler_client')
@patch('app.datetime')
def test_schedule_release_success(dt_mock, sched_mock, base_env):
    from datetime import datetime, timedelta
    dt_mock.datetime.utcnow.return_value = datetime(2024,1,1,0,0,0)
    dt_mock.timedelta = timedelta
    app._schedule_secret_release('sec-1', 60)
    sched_mock.create_schedule.assert_called_once()

@patch('app.scheduler_client')
def test_schedule_release_invalid_period(_, base_env):
    with pytest.raises(ValueError):
        app._schedule_secret_release('sec-1', 'bad')


# ---------------- POST Activation Core Paths ----------------
@patch('app._schedule_secret_release')
@patch('app._send_activation_email')
@patch('app._update_process_status_and_token', return_value=True)
@patch('app.hmac.compare_digest', return_value=True)
@patch('app._get_secret_config')
@patch('app.uuid.uuid4', return_value=Mock(__str__=lambda self: 'tok'))
def test_post_activation_success(uuid_mock, get_cfg, cmp_mock, upd_mock, email_mock, sched_mock, base_env, post_event_valid, config_item):
    get_cfg.return_value = config_item
    resp = app.verify_and_activate_process(post_event_valid, 'tbl')
    assert resp['statusCode'] == 200
    email_mock.assert_called_once()
    sched_mock.assert_called_once()

@patch('app._get_secret_config', return_value=None)
def test_post_activation_secret_not_found(_, base_env, post_event_valid):
    resp = app.verify_and_activate_process(post_event_valid, 'tbl')
    assert resp['statusCode'] == 401

@patch('app._get_secret_config', return_value={'passwordHashCr':'H','processStatus':'PENDING'})
def test_post_activation_conflict(_, base_env, post_event_valid):
    resp = app.verify_and_activate_process(post_event_valid, 'tbl')
    assert resp['statusCode'] == 409

@patch('app._get_secret_config', return_value={'passwordHashCr':'HH','processStatus':'INITIAL'})
@patch('app.hmac.compare_digest', return_value=False)
def test_post_activation_hash_mismatch(cmp_mock, get_cfg, base_env, post_event_valid):
    resp = app.verify_and_activate_process(post_event_valid, 'tbl')
    assert resp['statusCode'] == 401

@patch('app._get_secret_config', return_value={'passwordHashCr':'H','processStatus':'INITIAL','gracePeriodSeconds':50})
@patch('app.hmac.compare_digest', return_value=True)
@patch('app._update_process_status_and_token', return_value=False)
def test_post_activation_update_conflict(upd_mock, cmp_mock, get_cfg, base_env, post_event_valid):
    resp = app.verify_and_activate_process(post_event_valid, 'tbl')
    assert resp['statusCode'] == 409

@patch('app._get_secret_config', return_value={'passwordHashCr':'H','processStatus':'INITIAL','gracePeriodSeconds':50})
@patch('app.hmac.compare_digest', return_value=True)
@patch('app._update_process_status_and_token', return_value=True)
@patch('app._schedule_secret_release', side_effect=RuntimeError('fail'))
def test_post_activation_schedule_failure(sched_mock, upd_mock, cmp_mock, get_cfg, base_env, post_event_valid):
    resp = app.verify_and_activate_process(post_event_valid, 'tbl')
    assert resp['statusCode'] == 500


# ---------------- POST Input Validation ----------------
@pytest.mark.parametrize("body, code", [
    ("not-json", 400),
    (json.dumps({}), 400),
    (json.dumps({"secretId":"sec-1"}), 400),
    (json.dumps({"clientHash":"H"}), 400),
])
def test_post_activation_validation(body, code, base_env):
    event = {"httpMethod":"POST", "body": body}
    resp = app.verify_and_activate_process(event, 'tbl')
    assert resp['statusCode'] == code


# ---------------- lambda_handler dispatch ----------------
@patch('app.get_salt_for_secret', return_value={'statusCode':200,'body':'{}'})
def test_lambda_handler_get(dispatch_mock, base_env, context):
    resp = app.lambda_handler({'httpMethod':'GET','pathParameters':{'secretId':'sec'}}, context)
    assert resp['statusCode'] == 200

@patch('app.verify_and_activate_process', return_value={'statusCode':200,'body':'{}'})
def test_lambda_handler_post(dispatch_mock, base_env, context):
    resp = app.lambda_handler({'httpMethod':'POST','body':'{}'}, context)
    assert resp['statusCode'] == 200

def test_lambda_handler_method_not_allowed(base_env, context):
    resp = app.lambda_handler({'httpMethod':'PUT'}, context)
    assert resp['statusCode'] == 405

@patch.dict('os.environ', {}, clear=True)
def test_lambda_handler_missing_env(context):
    resp = app.lambda_handler({'httpMethod':'GET'}, context)
    assert resp['statusCode'] == 500
