"""Tests for the Flowtriq MISP expansion module."""

import json
from unittest.mock import patch, MagicMock

import pytest

from misp_modules.modules.expansion.flowtriq import handler, introspection, version


class TestIntrospection:
    def test_returns_input_output_types(self):
        result = introspection()
        assert 'input' in result
        assert 'output' in result
        assert 'ip-src' in result['input']
        assert 'ip-dst' in result['input']

    def test_format_is_misp_standard(self):
        result = introspection()
        assert result.get('format') == 'misp_standard'


class TestVersion:
    def test_returns_module_info(self):
        result = version()
        assert result['version'] == '1.0'
        assert result['author'] == 'Flowtriq'
        assert 'config' in result
        assert 'api_key' in result['config']
        assert 'api_url' in result['config']

    def test_module_type_includes_expansion(self):
        result = version()
        assert 'expansion' in result['module-type']
        assert 'hover' in result['module-type']


class TestHandler:
    def test_returns_false_when_no_input(self):
        assert handler(False) is False
        assert handler(q=False) is False

    def test_missing_api_key(self):
        request = json.dumps({
            'ip-src': '192.0.2.1',
            'config': {'api_key': '', 'api_url': 'https://flowtriq.com'},
        })
        result = handler(request)
        assert 'error' in result

    def test_missing_ip(self):
        request = json.dumps({
            'config': {'api_key': 'test-key'},
        })
        result = handler(request)
        assert 'error' in result

    @patch('misp_modules.modules.expansion.flowtriq.requests.post')
    def test_ip_not_found(self, mock_post):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'ok': True, 'found': False, 'ip': '192.0.2.1'}
        mock_post.return_value = mock_response

        request = json.dumps({
            'ip-src': '192.0.2.1',
            'config': {'api_key': 'test-key', 'api_url': 'https://flowtriq.example'},
        })
        result = handler(request)
        assert result == {'results': []}

    @patch('misp_modules.modules.expansion.flowtriq.requests.post')
    def test_successful_enrichment(self, mock_post):
        api_response = {
            'ok': True,
            'found': True,
            'ip': '203.0.113.50',
            'risk_score': 85,
            'reputation': {
                'attack_count': 12,
                'tenants_seen': 3,
                'first_seen': '2026-01-15T08:00:00Z',
                'last_seen': '2026-06-20T14:30:00Z',
                'top_attack_family': 'udp_flood',
                'top_protocol': 'UDP',
                'asn': 'AS12345',
                'country': 'RU',
                'peak_pps': 500000,
                'tags': ['botnet', 'mirai'],
            },
            'threat_intel': [
                {
                    'source': 'spamhaus_drop',
                    'indicator_type': 'ip',
                    'threat_type': 'Known Botnet C2',
                    'confidence': 90,
                    'description': 'Mirai botnet node',
                    'first_seen': '2026-01-01',
                    'last_seen': '2026-06-20',
                    'times_seen': 45,
                },
            ],
            'incidents': {
                'total': 8,
                'records': [
                    {
                        'attack_family': 'udp_flood',
                        'severity': 'high',
                        'peak_pps': 450000,
                        'peak_bps': 3600000000,
                        'source_ip_count': 1200,
                        'spoofing': False,
                        'botnet': True,
                        'duration_sec': 300,
                        'date': '2026-06-18',
                        'country': 'RU',
                        'asn': 'AS12345',
                    },
                ],
                'attack_families': {'udp_flood': 5, 'syn_flood': 3},
                'severity': {'critical': 1, 'high': 4, 'medium': 3, 'low': 0},
                'peak_pps': 500000,
                'protocols': {'UDP': 65.0, 'TCP': 35.0},
                'top_countries': {'RU': 40.0, 'CN': 25.0},
                'monthly_trend': {'2026-06': 3},
            },
            'ioc_matches': {'mirai_loader': 4, 'amplification_reflector': 2},
            'related_ips': {'198.51.100.10': 3, '198.51.100.20': 2},
        }

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = api_response
        mock_post.return_value = mock_response

        request = json.dumps({
            'ip-src': '203.0.113.50',
            'attribute': {'value': '203.0.113.50', 'type': 'ip-src'},
            'config': {'api_key': 'test-key', 'api_url': 'https://flowtriq.example'},
        })
        result = handler(request)

        assert 'results' in result
        results = result['results']
        assert len(results) > 0

        # Check summary text exists
        summary = results[0]
        assert summary['types'] == ['text']
        assert '85/100' in summary['values'][0]

        # Check related IPs are returned
        related_ip_values = []
        for r in results:
            if 'ip-src' in r.get('types', []):
                related_ip_values.extend(r['values'])
        assert '198.51.100.10' in related_ip_values

        # Check ASN is returned
        asn_results = [r for r in results if 'AS' in r.get('types', [])]
        assert len(asn_results) == 1
        assert asn_results[0]['values'] == ['AS12345']

    @patch('misp_modules.modules.expansion.flowtriq.requests.post')
    def test_api_connection_error(self, mock_post):
        import requests as req
        mock_post.side_effect = req.exceptions.ConnectionError('refused')

        request = json.dumps({
            'ip-src': '192.0.2.1',
            'config': {'api_key': 'test-key', 'api_url': 'https://flowtriq.example'},
        })
        result = handler(request)
        assert 'error' in result
        assert 'Cannot connect' in result['error']

    @patch('misp_modules.modules.expansion.flowtriq.requests.post')
    def test_api_timeout(self, mock_post):
        import requests as req
        mock_post.side_effect = req.exceptions.Timeout()

        request = json.dumps({
            'ip-src': '192.0.2.1',
            'config': {'api_key': 'test-key', 'api_url': 'https://flowtriq.example'},
        })
        result = handler(request)
        assert 'error' in result
        assert 'timed out' in result['error']

    @patch('misp_modules.modules.expansion.flowtriq.requests.post')
    def test_api_http_error(self, mock_post):
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_post.return_value = mock_response

        request = json.dumps({
            'ip-src': '192.0.2.1',
            'config': {'api_key': 'test-key', 'api_url': 'https://flowtriq.example'},
        })
        result = handler(request)
        assert 'error' in result
        assert '500' in result['error']

    @patch('misp_modules.modules.expansion.flowtriq.requests.post')
    def test_extracts_ip_from_attribute(self, mock_post):
        """Test that the handler can extract IP from the 'attribute' dict."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'ok': True, 'found': False}
        mock_post.return_value = mock_response

        request = json.dumps({
            'attribute': {'value': '10.0.0.1', 'type': 'ip-dst'},
            'config': {'api_key': 'test-key'},
        })
        result = handler(request)
        assert result == {'results': []}
        # Verify the API was called with the right IP
        call_args = mock_post.call_args
        assert call_args[1]['json']['ip'] == '10.0.0.1'

    @patch('misp_modules.modules.expansion.flowtriq.requests.post')
    def test_default_api_url(self, mock_post):
        """Test that missing api_url defaults to https://flowtriq.com."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'ok': True, 'found': False}
        mock_post.return_value = mock_response

        request = json.dumps({
            'ip-src': '192.0.2.1',
            'config': {'api_key': 'test-key', 'api_url': ''},
        })
        handler(request)
        call_url = mock_post.call_args[0][0]
        assert call_url.startswith('https://flowtriq.com/')

    @patch('misp_modules.modules.expansion.flowtriq.requests.post')
    def test_reputation_only_no_incidents(self, mock_post):
        """Test enrichment when there's reputation data but no incidents."""
        api_response = {
            'ok': True,
            'found': True,
            'ip': '198.51.100.5',
            'risk_score': 30,
            'reputation': {
                'attack_count': 2,
                'tenants_seen': 1,
                'first_seen': '2026-05-01',
                'last_seen': '2026-05-15',
                'top_attack_family': 'syn_flood',
                'top_protocol': 'TCP',
                'asn': 'AS99999',
                'country': 'US',
                'peak_pps': 10000,
                'tags': [],
            },
            'threat_intel': [],
            'incidents': {
                'total': 0,
                'records': [],
                'attack_families': {},
                'severity': {},
                'peak_pps': 0,
                'protocols': {},
                'top_countries': {},
                'monthly_trend': {},
            },
            'ioc_matches': {},
            'related_ips': {},
        }

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = api_response
        mock_post.return_value = mock_response

        request = json.dumps({
            'ip-src': '198.51.100.5',
            'config': {'api_key': 'test-key'},
        })
        result = handler(request)
        assert 'results' in result
        assert len(result['results']) > 0
        # Should have summary + reputation + ASN + timestamps but no incident records
        has_incident_text = any(
            'Incidents involving' in r['values'][0]
            for r in result['results']
            if r.get('types') == ['text']
        )
        assert not has_incident_text
