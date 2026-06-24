# Flowtriq MISP Modules

MISP expansion and export modules for Flowtriq DDoS intelligence.

## Modules

### Expansion: `flowtriq`

Enriches IP address attributes with DDoS attack intelligence from Flowtriq. When MISP users hover over or expand an IP, the module queries Flowtriq to check whether the IP has been observed as a DDoS attack source.

**Returns:**
- Risk score (0-100)
- IP reputation (attack count, networks seen, first/last seen, ASN, country)
- Incident history (attack families, severity, peak PPS/BPS, duration, spoofing/botnet flags)
- Related attacker IPs (co-occurring source IPs from the same incidents)
- Threat intel feed matches (Spamhaus, etc.)

**Supported input types:** `ip-src`, `ip-dst`

### Export: `flowtriq_export`

Exports `ip-src` attributes from MISP events back to Flowtriq's threat intelligence pipeline. This lets MISP sharing communities feed curated attacker IPs into Flowtriq, where they inform real-time attack classification and blocking decisions.

Only attributes with `to_ids=True` are exported. The module derives threat type and confidence from MISP event context (info field, tags, threat level).

## Installation

### Option 1: Copy into misp-modules

Copy the module files into your existing MISP modules installation:

```bash
# Expansion module
cp misp_modules/modules/expansion/flowtriq.py \
   /var/www/MISP/misp-modules/misp_modules/modules/expansion/

# Export module
cp misp_modules/modules/export/flowtriq_export.py \
   /var/www/MISP/misp-modules/misp_modules/modules/export/

# Logo (optional)
cp logo/flowtriq.png \
   /var/www/MISP/misp-modules/misp_modules/modules/expansion/logos/

# Restart misp-modules
sudo systemctl restart misp-modules
```

### Option 2: Symlink for development

```bash
ln -s $(pwd)/misp_modules/modules/expansion/flowtriq.py \
   /var/www/MISP/misp-modules/misp_modules/modules/expansion/flowtriq.py

ln -s $(pwd)/misp_modules/modules/export/flowtriq_export.py \
   /var/www/MISP/misp-modules/misp_modules/modules/export/flowtriq_export.py

sudo systemctl restart misp-modules
```

## Configuration

In MISP, go to **Administration > Server Settings & Maintenance > Plugin Settings > Enrichment** and configure:

| Setting | Description |
|---------|-------------|
| `api_key` | Your Flowtriq API key (from Dashboard > Settings > API) |
| `api_url` | Flowtriq API base URL (default: `https://flowtriq.com`) |

The same settings apply to both the expansion and export modules.

## Logo

Place a `flowtriq.png` file (128x128 recommended) at:

```
misp-modules/misp_modules/modules/expansion/logos/flowtriq.png
```

A logo file should be added at `logo/flowtriq.png` in this repository.

## How it works

### Expansion flow

1. User views an IP attribute in MISP and clicks "Enrich" (or hovers)
2. MISP calls the Flowtriq expansion module with the IP
3. Module queries `POST /api/ip-lookup.php` on the Flowtriq API
4. Flowtriq checks:
   - `ip_reputation` table (aggregated attack history)
   - `threat_intel_feed` table (curated feed matches)
   - `incidents` table (last 90 days of DDoS incidents involving this IP)
5. Module returns structured MISP attributes with the enrichment data

### Export flow

1. User selects events in MISP and chooses "Export as Flowtriq"
2. Module extracts all `ip-src` attributes with `to_ids=True`
3. For each IP, derives threat type from event info/tags and confidence from severity
4. Batch-pushes indicators to `POST /api/v1/threat-intel/import` on Flowtriq
5. Flowtriq ingests the IPs into its threat intel pipeline for real-time use

### Existing dashboard integration

Flowtriq's dashboard already has a built-in MISP integration that pushes DDoS incidents to MISP as events (configured under Dashboard > Integrations). These modules provide the reverse direction, letting MISP users query and export data back to Flowtriq.

## Testing

```bash
pip install -e ".[test]"
pytest tests/ -v
```

## Development

```
flowtriq-misp/
  misp_modules/
    modules/
      expansion/
        flowtriq.py          # IP enrichment module
      export/
        flowtriq_export.py   # Event export module
  tests/
    test_expansion.py
    test_export.py
  logo/
    flowtriq.png             # Module logo (to be added)
  .github/
    workflows/
      test.yml               # CI pipeline
  pyproject.toml
  README.md
```

## License

MIT
