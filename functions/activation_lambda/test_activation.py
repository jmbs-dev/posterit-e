import json
import pytest
from unittest.mock import Mock, patch
from botocore.exceptions import ClientError
import app

# ---------------- Fixtures ----------------
@pytest.fixture
def context():
    c = Mock()
    c.aws_request_id = "req"
    return c

@pytest.fixture
def base_env():
    with patch.dict('os.environ', {
        'DYNAMODB_TABLE_NAME': 'PosteritETable',
        'RELEASE_LAMBDA_ARN': 'rel-arn',
        'SCHEDULER_ROLE_ARN': 'sched-role',
        'SENDER_EMAIL_ADDRESS': 'sender@test.com',
        'BASE_URL': 'https://test.com'
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
        'processStatus': 'CREATED',
        'titularAlertContact': 'owner@example.com',
        'gracePeriodSeconds': 100
    }

# ---------------- GET Salt Tests ----------------
@patch('app._get_secret_config')
def test_get_salt_success(mock_get_cfg, base_env, get_event):
    mock_get_cfg.return_value = {'saltCr': 'saltX'}
    resp = app.get_salt_for_secret(get_event, 'tbl')
    assert resp['statusCode'] == 200
    assert 'saltX' in resp['body']

def test_get_salt_missing_id(base_env):
    resp = app.get_salt_for_secret({"httpMethod": "GET", "pathParameters": {}}, 'tbl')
    assert resp['statusCode'] == 409

@patch('app._get_secret_config')
def test_get_salt_not_found(mock_get_cfg, base_env, get_event):
    mock_get_cfg.return_value = {}
    resp = app.get_salt_for_secret(get_event, 'tbl')
    assert resp['statusCode'] == 401

# ---------------- Scheduling Helper ----------------
@patch('app.scheduler_client')
@patch('app.datetime')
def test_schedule_release_success(dt_mock, sched_mock, base_env):
    from datetime import datetime, timezone, timedelta
    dt_mock.datetime.now.return_value = datetime(2024, 1, 1, 0, 0, 0)
    dt_mock.timezone.utc = timezone.utc
    dt_mock.timedelta = timedelta
    app._schedule_secret_release('sec-1', 60)
    sched_mock.create_schedule.assert_called_once()

# ---------------- POST Activation Core Paths ----------------
@patch('app.dynamodb')
@patch('app._schedule_secret_release')
@patch('app._send_activation_email')
@patch('app.hmac.compare_digest', return_value=True)
@patch('app._get_secret_config')
def test_post_activation_success(mock_get_cfg, mock_hmac, mock_email, mock_schedule, mock_dynamodb, base_env, post_event_valid, config_item):
    """Happy path: config exists and is CREATED, hash matches, cancellation token exists, atomic update succeeds."""
    mock_get_cfg.return_value = config_item
    mock_table = Mock()
    mock_dynamodb.Table.return_value = mock_table
    mock_table.get_item.return_value = {
        'Item': {'tokenValue': 'existing-token-uuid'}
    }
    resp = app.verify_and_activate_process(post_event_valid, 'PosteritETable')
    assert resp['statusCode'] == 200
    mock_table.get_item.assert_called()
    mock_table.update_item.assert_called_once()
    mock_email.assert_called_with('owner@example.com', 'existing-token-uuid')
    mock_schedule.assert_called_once()

@patch('app._get_secret_config')
def test_post_activation_secret_not_found(mock_get_cfg, base_env, post_event_valid):
    mock_get_cfg.return_value = None
    resp = app.verify_and_activate_process(post_event_valid, 'tbl')
    assert resp['statusCode'] == 401

@patch('app._get_secret_config')
def test_post_activation_status_not_created(mock_get_cfg, base_env, post_event_valid):
    mock_get_cfg.return_value = {'passwordHashCr': 'H', 'processStatus': 'ACTIVATED'}
    resp = app.verify_and_activate_process(post_event_valid, 'tbl')
    assert resp['statusCode'] == 404

@patch('app._get_secret_config')
@patch('app.hmac.compare_digest', return_value=False)
def test_post_activation_hash_mismatch(mock_hmac, mock_get_cfg, base_env, post_event_valid, config_item):
    mock_get_cfg.return_value = config_item
    resp = app.verify_and_activate_process(post_event_valid, 'tbl')
    assert resp['statusCode'] == 401

@patch('app.dynamodb')
@patch('app._get_secret_config')
@patch('app.hmac.compare_digest', return_value=True)
def test_post_activation_token_missing_in_db(mock_hmac, mock_get_cfg, mock_dynamodb, base_env, post_event_valid, config_item):
    mock_get_cfg.return_value = config_item
    mock_table = Mock()
    mock_dynamodb.Table.return_value = mock_table
    mock_table.get_item.return_value = {}
    resp = app.verify_and_activate_process(post_event_valid, 'tbl')
    assert resp['statusCode'] == 500

@patch('app.dynamodb')
@patch('app._get_secret_config')
@patch('app.hmac.compare_digest', return_value=True)
def test_post_activation_concurrency_conflict(mock_hmac, mock_get_cfg, mock_dynamodb, base_env, post_event_valid, config_item):
    mock_get_cfg.return_value = config_item
    mock_table = Mock()
    mock_dynamodb.Table.return_value = mock_table
    mock_table.get_item.return_value = {'Item': {'tokenValue': 'ok'}}
    error_response = {'Error': {'Code': 'ConditionalCheckFailedException'}}
    mock_table.update_item.side_effect = ClientError(error_response, 'UpdateItem')
    resp = app.verify_and_activate_process(post_event_valid, 'tbl')
    assert resp['statusCode'] == 409

# ---------------- POST Input Validation ----------------
@pytest.mark.parametrize("body, code", [
    ("not-json", 409),
    (json.dumps({}), 409),
    (json.dumps({"secretId":"sec-1"}), 409),
])
def test_post_activation_validation(body, code, base_env):
    event = {"httpMethod": "POST", "body": body}
    resp = app.verify_and_activate_process(event, 'tbl')
    assert resp['statusCode'] == code

# ---------------- Dispatcher Tests ----------------
@patch('app.get_salt_for_secret', return_value={'statusCode':200})
def test_lambda_handler_get(mock_get, base_env, context):
    app.lambda_handler({'httpMethod':'GET'}, context)
    mock_get.assert_called()

@patch('app.verify_and_activate_process', return_value={'statusCode':200})
def test_lambda_handler_post(mock_post, base_env, context):
    app.lambda_handler({'httpMethod':'POST'}, context)
    mock_post.assert_called()