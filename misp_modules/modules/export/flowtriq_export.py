"""
Flowtriq DDoS Export Module for MISP

Exports MISP events containing DDoS indicators back to Flowtriq
as threat intelligence entries. This allows MISP communities to
feed curated attacker IPs into Flowtriq's threat intel pipeline,
where they inform real-time attack classification and blocking.

Extracts ip-src attributes from selected MISP events and pushes
them to the Flowtriq API with associated context (attack type,
severity, MISP event info).
"""

import json
import requests

misperrors = {'error': 'Error'}
mispattributes = {}
moduleinfo = {
    'version': '1.0',
    'author': 'Flowtriq',
    'description': 'Export DDoS indicators from MISP events to Flowtriq threat intel',
    'module-type': ['export'],
    'name': 'Flowtriq DDoS Export',
    'logo': 'flowtriq.png',
    'requirements': ['Flowtriq API key and API URL'],
    'features': (
        'Exports ip-src attributes from MISP events to the Flowtriq '
        'threat intelligence feed. Supports batch export of multiple '
        'events. Includes MISP event context (info, threat level, tags) '
        'as metadata in the Flowtriq threat entry.'
    ),
    'references': ['https://flowtriq.com'],
    'input': 'MISP events with ip-src attributes.',
    'output': 'Threat intel entries in Flowtriq.',
}
moduleconfig = ['api_key', 'api_url']
modulesetup = {}

_DEFAULT_API_URL = 'https://flowtriq.com'
_TIMEOUT = 20
_BATCH_SIZE = 100

# MISP threat_level_id mapping
_MISP_THREAT_LEVELS = {
    '1': 'high',
    '2': 'medium',
    '3': 'low',
    '4': 'undefined',
}


def handler(q=False):
    if q is False:
        return False

    request = json.loads(q)

    config = request.get('config', {})
    api_key = config.get('api_key', '').strip()
    api_url = config.get('api_url', '').strip().rstrip('/') or _DEFAULT_API_URL

    if not api_key:
        misperrors['error'] = 'Flowtriq API key is required.'
        return misperrors

    # MISP export modules receive a 'data' key with list of events
    events = request.get('data', [])
    if not events:
        return {'response': [], 'data': ''}

    indicators = []
    for event in events:
        event_data = event.get('Event', event)
        event_info = event_data.get('info', '')
        event_date = event_data.get('date', '')
        threat_level = _MISP_THREAT_LEVELS.get(
            str(event_data.get('threat_level_id', '4')), 'undefined'
        )

        # Collect tags from the event
        event_tags = []
        for tag in event_data.get('Tag', []):
            tag_name = tag.get('name', '')
            if tag_name:
                event_tags.append(tag_name)

        attributes = event_data.get('Attribute', [])
        for attr in attributes:
            if attr.get('type') != 'ip-src':
                continue
            if not attr.get('to_ids', False):
                continue

            ip = attr.get('value', '').strip()
            if not ip:
                continue

            comment = attr.get('comment', '')
            indicators.append({
                'ip': ip,
                'source': 'misp',
                'threat_type': _derive_threat_type(event_info, event_tags, comment),
                'confidence': _derive_confidence(attr, threat_level),
                'description': _build_description(event_info, comment, event_date),
                'severity': threat_level,
                'tags': event_tags[:10],
                'misp_event_info': event_info[:200],
            })

    if not indicators:
        return {'response': [], 'data': ''}

    # Push indicators to Flowtriq in batches
    errors = []
    exported = 0
    for batch_start in range(0, len(indicators), _BATCH_SIZE):
        batch = indicators[batch_start:batch_start + _BATCH_SIZE]
        try:
            response = requests.post(
                f'{api_url}/api/v1/threat-intel/import',
                json={'indicators': batch, 'source': 'misp'},
                headers={
                    'Authorization': f'Bearer {api_key}',
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'User-Agent': 'MISP-Flowtriq-Export/1.0',
                },
                timeout=_TIMEOUT,
                verify=True,
            )
            if response.status_code in (200, 201):
                resp_data = response.json()
                exported += resp_data.get('imported', len(batch))
            else:
                errors.append(f'HTTP {response.status_code}: {response.text[:200]}')
        except requests.exceptions.RequestException as e:
            errors.append(str(e))

    output_lines = [f'Exported {exported} indicator(s) to Flowtriq.']
    if errors:
        output_lines.append(f'Errors ({len(errors)}):')
        for err in errors[:5]:
            output_lines.append(f'  - {err}')

    return {
        'response': output_lines,
        'data': '\n'.join(output_lines),
    }


def _derive_threat_type(event_info, tags, comment):
    """Derive a threat type string from MISP event context."""
    info_lower = (event_info + ' ' + comment).lower()

    # Check for DDoS-specific patterns
    ddos_keywords = {
        'udp flood': 'udp_flood',
        'syn flood': 'syn_flood',
        'tcp flood': 'tcp_flood',
        'dns amplification': 'dns_amplification',
        'ntp amplification': 'ntp_amplification',
        'memcached': 'memcached_amplification',
        'ssdp': 'ssdp_amplification',
        'chargen': 'chargen_amplification',
        'cldap': 'cldap_amplification',
        'icmp flood': 'icmp_flood',
        'http flood': 'http_flood',
        'slowloris': 'slowloris',
        'botnet': 'botnet',
        'mirai': 'botnet_mirai',
        'ddos': 'ddos',
        'amplification': 'amplification',
        'reflection': 'reflection',
    }
    for keyword, threat_type in ddos_keywords.items():
        if keyword in info_lower:
            return threat_type

    # Check tags
    for tag in tags:
        tag_lower = tag.lower()
        if 'ddos' in tag_lower:
            return 'ddos'
        if 'botnet' in tag_lower:
            return 'botnet'

    return 'ddos_source'


def _derive_confidence(attribute, threat_level):
    """Derive a confidence score (0-100) from MISP attribute and event context."""
    base = 60

    # IDS-flagged attributes get a boost
    if attribute.get('to_ids'):
        base += 10

    # Threat level affects confidence
    level_boost = {'high': 15, 'medium': 5, 'low': 0, 'undefined': 0}
    base += level_boost.get(threat_level, 0)

    # Correlation count (if available)
    correlations = int(attribute.get('event_count', attribute.get('correlations', 0)) or 0)
    if correlations > 5:
        base += 10
    elif correlations > 1:
        base += 5

    return min(100, base)


def _build_description(event_info, comment, event_date):
    """Build a human-readable description for the Flowtriq threat entry."""
    parts = []
    if event_info:
        parts.append(event_info[:150])
    if comment:
        parts.append(comment[:100])
    if event_date:
        parts.append(f'MISP event date: {event_date}')
    return ' | '.join(parts) if parts else 'Imported from MISP'


def introspection():
    modulesetup['responseType'] = 'application/txt'
    return modulesetup


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo
