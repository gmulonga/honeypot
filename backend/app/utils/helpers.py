import ipaddress
from datetime import datetime, timedelta
from typing import Optional, Dict, Any

def is_valid_ip(ip: str) -> bool:
    """Check if IP address is valid"""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def parse_timestamp(timestamp_str: str) -> Optional[datetime]:
    """Parse timestamp string to datetime object"""
    formats = [
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S.%f",
    ]
    
    for fmt in formats:
        try:
            return datetime.strptime(timestamp_str, fmt)
        except ValueError:
            continue
    
    # Try Unix timestamp
    try:
        return datetime.fromtimestamp(float(timestamp_str))
    except:
        return None

def calculate_time_range(start: Optional[datetime] = None, end: Optional[datetime] = None) -> tuple:
    """Calculate time range for queries"""
    if not end:
        end = datetime.now()
    if not start:
        start = end - timedelta(days=7)
    
    return start, end

def group_by_time(records: list, time_field: str = 'timestamp', interval: str = 'hour') -> Dict[str, int]:
    """Group records by time interval"""
    grouped = {}
    
    for record in records:
        if time_field in record:
            dt = parse_timestamp(record[time_field])
            if dt:
                if interval == 'hour':
                    key = dt.strftime("%Y-%m-%d %H:00")
                elif interval == 'day':
                    key = dt.strftime("%Y-%m-%d")
                elif interval == 'month':
                    key = dt.strftime("%Y-%m")
                else:
                    key = dt.strftime("%Y-%m-%d %H:%M")
                
                grouped[key] = grouped.get(key, 0) + 1
    
    return dict(sorted(grouped.items()))