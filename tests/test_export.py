"""Tests for the Flowtriq MISP export module."""

import json
from unittest.mock import patch, MagicMock

import pytest

from misp_modules.modules.export.flowtriq_export import handler, introspection, version


class TestIntrospection:
    def test_returns_response_type(self):
        result = introspection()
        assert result.get('responseType') == 'application/txt'


class TestVersion:
    def test_returns_module_info(self):
        result = version()
        assert result['version'] == '1.0'
        assert 'export' in result['module-type']
        assert 'config' in result
        assert 'api_key' in result['config']


class TestHandler:
    def test_returns_false_when_no_input(self):
        assert handler(False) is False

    def test_missing_api_key(self):
        request = json.dumps({
            'config': {'api_key': ''},
            'data': [],
        })
        result = handler(request)
        assert 'error' in result

    def test_empty_events(self):
        request = json.dumps({
            'config': {'api_key': 'test-key'},
            'data': [],
        })
        result = handler(request)
        assert result['data'] == ''

    def test_no_ip_src_attributes(self):
        """Events with only non-ip-src attributes should export nothing."""
        request = json.dumps({
            'config': {'api_key': 'test-key', 'api_url': 'https://ft.example'},
            'data': [{
                'Event': {
                    'info': 'Test event',
                    'date': '2026-06-20',
                    'threat_level_id': '2',
                    'Attribute': [
                        {'type': 'domain', 'value': 'evil.example', 'to_ids': True},
                        {'type': 'ip-dst', 'value': '10.0.0.1', 'to_ids': True},
                    ],
                    'Tag': [],
                },
            }],
        })
        result = handler(request)
        assert result['data'] == ''

    def test_skips_non_ids_attributes(self):
        """Attributes with to_ids=False should be skipped."""
        request = json.dumps({
            'config': {'api_key': 'test-key', 'api_url': 'https://ft.example'},
            'data': [{
                'Event': {
                    'info': 'Test',
                    'date': '2026-06-20',
                    'threat_level_id': '2',
                    'Attribute': [
                        {'type': 'ip-src', 'value': '192.0.2.1', 'to_ids': False},
                    ],
                    'Tag': [],
                },
            }],
        })
        result = handler(request)
        assert result['data'] == ''

    @patch('misp_modules.modules.export.flowtriq_export.requests.post')
    def test_successful_export(self, mock_post):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'ok': True, 'imported': 2}
        mock_post.return_value = mock_response

        request = json.dumps({
            'config': {'api_key': 'test-key', 'api_url': 'https://ft.example'},
            'data': [{
                'Event': {
                    'info': 'Flowtriq: UDP Flood DDoS on node-1',
                    'date': '2026-06-18',
                    'threat_level_id': '1',
                    'Attribute': [
                        {'type': 'ip-src', 'value': '203.0.113.10', 'to_ids': True,
                         'comment': 'DDoS source IP'},
                        {'type': 'ip-src', 'value': '203.0.113.11', 'to_ids': True,
                         'comment': 'DDoS source IP'},
                        {'type': 'ip-dst', 'value': '198.51.100.1', 'to_ids': False,
                         'comment': 'Attacked node'},
                    ],
                    'Tag': [
                        {'name': 'tlp:green'},
                        {'name': 'ddos'},
                    ],
                },
            }],
        })
        result = handler(request)
        assert 'Exported 2 indicator(s)' in result['data']

        # Verify the API was called
        call_args = mock_post.call_args
        payload = call_args[1]['json']
        assert payload['source'] == 'misp'
        assert len(payload['indicators']) == 2
        assert payload['indicators'][0]['ip'] == '203.0.113.10'
        assert payload['indicators'][0]['threat_type'] == 'udp_flood'
        assert payload['indicators'][0]['severity'] == 'high'

    @patch('misp_modules.modules.export.flowtriq_export.requests.post')
    def test_api_error_reported(self, mock_post):
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_response.text = 'Internal server error'
        mock_post.return_value = mock_response

        request = json.dumps({
            'config': {'api_key': 'test-key', 'api_url': 'https://ft.example'},
            'data': [{
                'Event': {
                    'info': 'Test',
                    'threat_level_id': '2',
                    'Attribute': [
                        {'type': 'ip-src', 'value': '192.0.2.1', 'to_ids': True},
                    ],
                    'Tag': [],
                },
            }],
        })
        result = handler(request)
        assert 'Exported 0 indicator(s)' in result['data']
        assert 'Errors' in result['data']

    @patch('misp_modules.modules.export.flowtriq_export.requests.post')
    def test_connection_error_reported(self, mock_post):
        import requests as req
        mock_post.side_effect = req.exceptions.ConnectionError('refused')

        request = json.dumps({
            'config': {'api_key': 'test-key', 'api_url': 'https://ft.example'},
            'data': [{
                'Event': {
                    'info': 'Test',
                    'threat_level_id': '3',
                    'Attribute': [
                        {'type': 'ip-src', 'value': '192.0.2.1', 'to_ids': True},
                    ],
                    'Tag': [],
                },
            }],
        })
        result = handler(request)
        assert 'Errors' in result['data']

    @patch('misp_modules.modules.export.flowtriq_export.requests.post')
    def test_threat_type_detection(self, mock_post):
        """Test that threat types are derived from MISP event context."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'ok': True, 'imported': 1}
        mock_post.return_value = mock_response

        request = json.dumps({
            'config': {'api_key': 'test-key', 'api_url': 'https://ft.example'},
            'data': [{
                'Event': {
                    'info': 'DNS Amplification attack from botnet',
                    'threat_level_id': '1',
                    'Attribute': [
                        {'type': 'ip-src', 'value': '192.0.2.1', 'to_ids': True},
                    ],
                    'Tag': [],
                },
            }],
        })
        handler(request)
        payload = mock_post.call_args[1]['json']
        assert payload['indicators'][0]['threat_type'] == 'dns_amplification'

    @patch('misp_modules.modules.export.flowtriq_export.requests.post')
    def test_multiple_events(self, mock_post):
        """Test exporting from multiple MISP events."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'ok': True, 'imported': 3}
        mock_post.return_value = mock_response

        request = json.dumps({
            'config': {'api_key': 'test-key', 'api_url': 'https://ft.example'},
            'data': [
                {
                    'Event': {
                        'info': 'Event 1',
                        'threat_level_id': '2',
                        'Attribute': [
                            {'type': 'ip-src', 'value': '10.0.0.1', 'to_ids': True},
                            {'type': 'ip-src', 'value': '10.0.0.2', 'to_ids': True},
                        ],
                        'Tag': [],
                    },
                },
                {
                    'Event': {
                        'info': 'Event 2',
                        'threat_level_id': '1',
                        'Attribute': [
                            {'type': 'ip-src', 'value': '10.0.0.3', 'to_ids': True},
                        ],
                        'Tag': [],
                    },
                },
            ],
        })
        result = handler(request)
        assert 'Exported 3 indicator(s)' in result['data']
        payload = mock_post.call_args[1]['json']
        assert len(payload['indicators']) == 3
