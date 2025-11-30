import sys, os
sys.path.insert(0, os.path.dirname(__file__))
import json
import base64
import pytest
from unittest.mock import Mock, patch
from botocore.exceptions import ClientError
import app

# ---------- Fixtures ----------
@pytest.fixture
def context():
    ctx = Mock()
    ctx.aws_request_id = "req-1"
    return ctx

@pytest.fixture
def env_vars():
    with patch.dict('os.environ', {'DYNAMODB_TABLE_NAME': 'tbl', 'S3_BUCKET_NAME': 'bucket'}):
        yield

@pytest.fixture
def valid_body_dict():
    return {
        'encryptedSecret': base64.b64encode(b'data').decode(),
        'encryptedDek': 'dek',
        'saltKek': 'saltKek',
        'saltCr': 'saltCr',
        'passwordHashCr': 'hash',
        'beneficiaryContact': 'b@example.com',
        'gracePeriodSeconds': 3600,
        'titularAlertContact': 'o@example.com'
    }

@pytest.fixture
def valid_event(valid_body_dict):
    return {'body': json.dumps(valid_body_dict)}

# ---------- _parse_and_validate_body ----------
@pytest.mark.parametrize("event, expected_substr", [
    ({'body': '{}'}, "cannot be empty"),
    ({'body': json.dumps({'encryptedSecret': 'x'})}, "'encryptedDek'"),
])
def test_parse_and_validate_body_invalid(event, expected_substr):
    with pytest.raises(app.ValidationException) as e:
        app._parse_and_validate_body(event)
    assert expected_substr in str(e.value)

def test_parse_and_validate_body_success(valid_event):
    body = app._parse_and_validate_body(valid_event)
    assert body['encryptedSecret']

# ---------- _upload_secret_to_s3 ----------
@patch('app.s3_client')
def test_upload_secret_to_s3_success(s3_mock):
    app._upload_secret_to_s3('b', 'k', base64.b64encode(b'abc').decode())
    s3_mock.put_object.assert_called_once()

def test_upload_secret_to_s3_invalid_base64():
    with pytest.raises(app.ValidationException):
        app._upload_secret_to_s3('b', 'k', '!!notb64!!')

# ---------- _prepare_dynamodb_items ----------
def test_prepare_dynamodb_items(valid_body_dict):
    metadata = {
        'secret_id': 'sec-1',
        's3_object_key': 'sec-1',
        'created_at_iso': '2024-01-01T00:00:00',
        'gracePeriodSeconds': 3600,
    }
    cfg, payload = app._prepare_dynamodb_items(valid_body_dict, metadata)
    assert cfg['PK'] == 'SECRET#sec-1'
    assert payload['s3ObjectKey'] == 'sec-1'

# ---------- lambda_handler (integration happy path + key error branches) ----------
@patch.dict('os.environ', {'DYNAMODB_TABLE_NAME': 'tbl', 'S3_BUCKET_NAME': 'bucket'})
@patch('app._upload_secret_to_s3')
@patch('app.dynamodb')
@patch('app._generate_server_side_metadata')
def test_lambda_handler_success(meta_mock, ddb_mock, upload_mock, valid_event, context):
    meta_mock.return_value = {
        'secret_id': 'sec-1',
        's3_object_key': 'sec-1',
        'created_at_iso': 'X',
        'gracePeriodSeconds': 3600
    }
    ddb_mock.meta.client.transact_write_items.return_value = {}
    resp = app.lambda_handler(valid_event, context)
    assert resp['statusCode'] == 201
    body = json.loads(resp['body'])
    assert body['secretId'] == 'sec-1'

@patch.dict('os.environ', {'DYNAMODB_TABLE_NAME': 'tbl', 'S3_BUCKET_NAME': 'bucket'})
def test_lambda_handler_validation_error(context):
    resp = app.lambda_handler({'body': '{}'}, context)
    assert resp['statusCode'] == 400

@patch.dict('os.environ', {'DYNAMODB_TABLE_NAME': 'tbl', 'S3_BUCKET_NAME': 'bucket'})
@patch('app._upload_secret_to_s3')
@patch('app.dynamodb')
@patch('app._generate_server_side_metadata')
def test_lambda_handler_aws_client_error(meta_mock, ddb_mock, upload_mock, valid_event, context):
    meta_mock.return_value = {
        'secret_id': 'sec-1', 's3_object_key': 'sec-1', 'created_at_iso': 'X', 'gracePeriodSeconds': 3600
    }
    ddb_mock.meta.client.transact_write_items.side_effect = ClientError(
        {'Error': {'Code': 'ValidationException', 'Message': 'x'}}, 'TransactWriteItems')
    resp = app.lambda_handler(valid_event, context)
    assert resp['statusCode'] == 500
    assert 'Server Error' in resp['body']

@patch.dict('os.environ', {'DYNAMODB_TABLE_NAME': 'tbl', 'S3_BUCKET_NAME': 'bucket'})
@patch('app._upload_secret_to_s3')
@patch('app._generate_server_side_metadata')
@patch('app.dynamodb')
def test_lambda_handler_unexpected_error(ddb_mock, meta_mock, upload_mock, context, valid_event):
    meta_mock.side_effect = RuntimeError('boom')
    resp = app.lambda_handler(valid_event, context)
    assert resp['statusCode'] == 500
    assert 'Internal Server Error' in resp['body']

@patch.dict('os.environ', {'DYNAMODB_TABLE_NAME': 'tbl', 'S3_BUCKET_NAME': 'bucket'})
@patch('app._upload_secret_to_s3')
@patch('app._generate_server_side_metadata')
@patch('app.dynamodb')
def test_lambda_handler_non_numeric_grace_period(ddb_mock, meta_mock, upload_mock, context, valid_body_dict):
    bad_body = valid_body_dict.copy()
    bad_body['gracePeriodSeconds'] = 'notanumber'
    event = {'body': json.dumps(bad_body)}
    # int() will raise ValueError -> captured by generic exception handler => 500
    resp = app.lambda_handler(event, context)
    assert resp['statusCode'] == 500

@patch('app._upload_secret_to_s3')
@patch('app._generate_server_side_metadata')
@patch('app.dynamodb')
@patch.dict('os.environ', {'DYNAMODB_TABLE_NAME': 'tbl'})
def test_lambda_handler_missing_one_env(ddb_mock, meta_mock, upload_mock, context, valid_event):
    # Missing S3_BUCKET_NAME -> KeyError -> 500
    resp = app.lambda_handler(valid_event, context)
    assert resp['statusCode'] == 500

@patch.dict('os.environ', {'DYNAMODB_TABLE_NAME': 'tbl', 'S3_BUCKET_NAME': 'bucket'})
@patch('app._upload_secret_to_s3')
@patch('app.dynamodb')
@patch('app._generate_server_side_metadata')
def test_lambda_handler_extra_unknown_fields(meta_mock, ddb_mock, upload_mock, context, valid_body_dict):
    meta_mock.return_value = {
        'secret_id': 'sec-x', 's3_object_key': 'sec-x', 'created_at_iso': 'X', 'gracePeriodSeconds': 3600
    }
    ddb_mock.meta.client.transact_write_items.return_value = {}
    body = valid_body_dict.copy()
    body['someUnusedField'] = 'ignore'
    event = {'body': json.dumps(body)}
    resp = app.lambda_handler(event, context)
    assert resp['statusCode'] == 201

@patch.dict('os.environ', {'DYNAMODB_TABLE_NAME': 'tbl', 'S3_BUCKET_NAME': 'bucket'})
@patch('app.s3_client')
def test_upload_secret_to_s3_unexpected_exception(s3_mock):
    s3_mock.put_object.side_effect = ValueError('boom')
    with pytest.raises(ValueError):
        # This bubbles (non ClientError) - validated indirectly maybe not needed in handler but good unit test
        app._upload_secret_to_s3('bucket', 'key', base64.b64encode(b'abc').decode())

@patch.dict('os.environ', {'DYNAMODB_TABLE_NAME': 'tbl', 'S3_BUCKET_NAME': 'bucket'})
@patch('app._upload_secret_to_s3', return_value=None)
@patch('app._generate_server_side_metadata')
@patch('app.dynamodb')
def test_lambda_handler_empty_encrypted_secret(ddb_mock, meta_mock, upload_mock, context, valid_body_dict):
    meta_mock.return_value = {
        'secret_id': 'sec-empty', 's3_object_key': 'sec-empty', 'created_at_iso': 'X', 'gracePeriodSeconds': 3600
    }
    ddb_mock.meta.client.transact_write_items.return_value = {}
    body = valid_body_dict.copy()
    body['encryptedSecret'] = ''  # empty still base64 decodes to b'' -> accepted
    event = {'body': json.dumps(body)}
    resp = app.lambda_handler(event, context)
    assert resp['statusCode'] == 201

