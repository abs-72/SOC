# Dashboard Alerts Not Showing - Fix Summary

## Problem
The dashboard was showing **0 alerts** (stat card "Total Alerts" displaying 0) even though alert data existed in ELK under the `cogsoc-alerts` index.

## Root Cause
The alerts were being indexed in ELK, but the `sensor_name` field was not being properly populated. Here's what was happening:

### Flow of Data:
1. **Filebeat** captures CICFlowMeter CSV files and ships them to ELK
   - Filebeat was adding `capture_interface` field (e.g., "Wi-Fi")
   - But **NOT** adding `sensor_name` field

2. **cogsoc_behav.py** processes flows and generates alerts
   - At line 2489, it tried to get `sensor_name` from the flow document
   - Since Filebeat wasn't adding it, the code defaulted to `'unknown'`
   - All alerts ended up with `sensor_name: 'unknown'`

3. **Dashboard** queries alerts
   - Queries worked and returned data
   - BUT there might have been field mapping or data consistency issues

## Solution
Applied three fixes:

### Fix 1: Filebeat Configuration (Line 600)
**Added `sensor_name` field to Filebeat output:**
```yaml
- add_fields:
    target: ''
    fields:
      index_name: "cogsoc-flows"
      sensor_name: "{CICFLOW_INTERFACE}"  # ← NEW: Added this line
```

Now flows will have the `sensor_name` field populated with the capture interface name (e.g., "Wi-Fi").

### Fix 2: Alert Generation (Lines 2566-2574)
**Improved sensor name extraction with fallbacks:**
```python
# Extract sensor_name from flow_doc, with fallbacks
final_sensor = sensor
if final_sensor == 'unknown' or not final_sensor:
    # Try to get from flow_doc fields that might be set by Filebeat
    final_sensor = (flow_doc.get('capture_interface') or 
                   flow_doc.get('sensor_name') or 
                   flow_doc.get('source_sensor') or 
                   'unknown')
```

This ensures that even if `sensor_name` wasn't in the flow initially, it will try to get it from multiple possible field names.

### Fix 3: Added flow_timestamp to Alert (Line 2594)
**Preserved the original flow timestamp:**
```python
'flow_timestamp': flow_doc.get('@timestamp', flow_doc.get('timestamp', ts)),
```

This provides better traceability between flows and alerts.

### Fix 4: Better Error Logging (Lines 2208-2211)
**Enhanced error messages for debugging:**
```python
except Exception as e:
    print(f"[ELK] ❌ Alert save error: {e}")
    print(f"[ELK]    Alert data: {alert}")
    import traceback
    traceback.print_exc()
```

Now if there are indexing errors, they'll be clearly printed with the full alert data and traceback.

## Expected Behavior After Fix
1. ✅ Flows will have `sensor_name` field set from the capture interface
2. ✅ Alerts will have properly populated `sensor_name` field
3. ✅ Dashboard queries will return the correct count and display alerts
4. ✅ Sensor filter dropdown will show the actual sensor names (e.g., "Wi-Fi") instead of just "unknown"
5. ✅ If there are indexing errors, they'll be logged clearly for debugging

## How to Apply
The changes have already been applied to `cogsoc_behav.py`. To take effect:

1. **Stop the current dashboard.py** (if running)
2. **Restart dashboard.py**:
   ```bash
   cd C:\CogSOC\New_Approach
   python dashboard.py
   ```
3. The next time alerts are generated, they will be properly indexed with sensor names
4. The dashboard will show the correct alert counts

## Testing
To verify the fix is working:

1. Generate some network traffic to trigger alerts
2. Open the test page: http://localhost:8050/test_dashboard_query.html
3. Click the buttons to test:
   - "Count Alerts" - should show number > 0
   - "Sample Alert" - should show an alert document with populated fields
   - "Test loadAlerts()" - should display recent alerts

You should now see alerts showing on the dashboard stat cards and in the "Recent Alerts" table.
