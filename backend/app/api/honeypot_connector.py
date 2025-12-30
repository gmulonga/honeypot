import asyncio
import aiohttp
import json
from datetime import datetime
from typing import Optional, Dict, Any, List
import uuid
from enum import Enum
import logging

from app.models.schemas import HoneypotType, AttackPattern
from app.services.log_processor import LogProcessor
from app.services.threat_intelligence import ThreatAnalyzer

logger = logging.getLogger(__name__)

class HoneypotConnectionStatus(str, Enum):
    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    ERROR = "error"
    FETCHING = "fetching"

class HoneypotConnector:
    """Connector for various honeypot types to fetch logs in real-time"""
    
    def __init__(self, connection_config: Dict[str, Any]):
        self.connection_id = str(uuid.uuid4())
        self.config = connection_config
        self.name = connection_config.get('name', 'Unnamed Honeypot')
        self.honeypot_type = HoneypotType(connection_config.get('honeypot_type', 't-pot'))
        self.api_url = connection_config.get('api_url')
        self.api_key = connection_config.get('api_key')
        self.username = connection_config.get('username')
        self.password = connection_config.get('password')
        
        self.status = HoneypotConnectionStatus.DISCONNECTED
        self.last_fetch = None
        self.total_logs_fetched = 0
        self.is_running = False
        self.session = None
        
        # Buffer for storing fetched logs
        self.log_buffer = []
        self.max_buffer_size = 1000
        
        # Rate limiting
        self.fetch_interval = 30  # seconds
        
    async def test_connection(self) -> bool:
        """Test connection to honeypot"""
        try:
            if self.honeypot_type == HoneypotType.T_POT:
                return await self._test_tpot_connection()
            elif self.honeypot_type == HoneypotType.COWRIE:
                return await self._test_cowrie_connection()
            elif self.honeypot_type == HoneypotType.DIONAEA:
                return await self._test_dionaea_connection()
            else:
                return await self._test_generic_connection()
        except Exception as e:
            logger.error(f"Connection test failed: {e}")
            return False
    
    async def _test_tpot_connection(self) -> bool:
        """Test T-Pot connection"""
        try:
            url = f"{self.api_url.rstrip('/')}/api/info"
            async with aiohttp.ClientSession() as session:
                headers = {}
                if self.api_key:
                    headers['Authorization'] = f'Bearer {self.api_key}'
                
                async with session.get(url, headers=headers, timeout=10) as response:
                    if response.status == 200:
                        data = await response.json()
                        logger.info(f"Connected to T-Pot: {data.get('version', 'Unknown')}")
                        return True
                    else:
                        logger.error(f"T-Pot connection failed: {response.status}")
                        return False
        except Exception as e:
            logger.error(f"T-Pot connection error: {e}")
            return False
    
    async def _test_cowrie_connection(self) -> bool:
        """Test Cowrie connection"""
        try:
            # Cowrie usually exposes logs via REST API or direct log file access
            url = f"{self.api_url.rstrip('/')}/api/sessions"
            async with aiohttp.ClientSession() as session:
                auth = None
                if self.username and self.password:
                    auth = aiohttp.BasicAuth(self.username, self.password)
                
                async with session.get(url, auth=auth, timeout=10) as response:
                    if response.status in [200, 201]:
                        logger.info("Connected to Cowrie honeypot")
                        return True
                    else:
                        logger.error(f"Cowrie connection failed: {response.status}")
                        return False
        except Exception as e:
            logger.error(f"Cowrie connection error: {e}")
            return False
    
    async def _test_dionaea_connection(self) -> bool:
        """Test Dionaea connection"""
        try:
            # Dionaea typically provides JSON logs via HTTP
            url = f"{self.api_url.rstrip('/')}/stats"
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=10) as response:
                    if response.status == 200:
                        logger.info("Connected to Dionaea honeypot")
                        return True
                    else:
                        logger.error(f"Dionaea connection failed: {response.status}")
                        return False
        except Exception as e:
            logger.error(f"Dionaea connection error: {e}")
            return False
    
    async def _test_generic_connection(self) -> bool:
        """Test generic honeypot connection"""
        try:
            url = self.api_url
            async with aiohttp.ClientSession() as session:
                headers = {'Accept': 'application/json'}
                if self.api_key:
                    headers['Authorization'] = f'Bearer {self.api_key}'
                
                async with session.get(url, headers=headers, timeout=10) as response:
                    if response.status in [200, 201]:
                        logger.info(f"Connected to generic honeypot: {self.name}")
                        return True
                    else:
                        logger.error(f"Generic connection failed: {response.status}")
                        return False
        except Exception as e:
            logger.error(f"Generic connection error: {e}")
            return False
    
    async def fetch_logs(self) -> List[Dict[str, Any]]:
        """Fetch logs from honeypot"""
        self.status = HoneypotConnectionStatus.FETCHING
        
        try:
            if self.honeypot_type == HoneypotType.T_POT:
                logs = await self._fetch_tpot_logs()
            elif self.honeypot_type == HoneypotType.COWRIE:
                logs = await self._fetch_cowrie_logs()
            elif self.honeypot_type == HoneypotType.DIONAEA:
                logs = await self._fetch_dionaea_logs()
            else:
                logs = await self._fetch_generic_logs()
            
            self.last_fetch = datetime.now()
            self.total_logs_fetched += len(logs)
            
            # Add to buffer
            self.log_buffer.extend(logs)
            if len(self.log_buffer) > self.max_buffer_size:
                self.log_buffer = self.log_buffer[-self.max_buffer_size:]
            
            self.status = HoneypotConnectionStatus.CONNECTED
            return logs
            
        except Exception as e:
            logger.error(f"Error fetching logs: {e}")
            self.status = HoneypotConnectionStatus.ERROR
            return []
    
    async def _fetch_tpot_logs(self) -> List[Dict[str, Any]]:
        """Fetch logs from T-Pot"""
        try:
            # T-Pot typically provides logs through Elasticsearch API
            url = f"{self.api_url.rstrip('/')}/api/logs"
            
            # Add timestamp filter to get new logs only
            params = {}
            if self.last_fetch:
                params['since'] = self.last_fetch.isoformat()
            
            async with aiohttp.ClientSession() as session:
                headers = {}
                if self.api_key:
                    headers['Authorization'] = f'Bearer {self.api_key}'
                
                async with session.get(url, headers=headers, params=params, timeout=30) as response:
                    if response.status == 200:
                        data = await response.json()
                        return self._parse_tpot_logs(data)
                    else:
                        logger.error(f"Failed to fetch T-Pot logs: {response.status}")
                        return []
        except Exception as e:
            logger.error(f"Error fetching T-Pot logs: {e}")
            return []
    
    def _parse_tpot_logs(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Parse T-Pot log data"""
        logs = []
        
        # T-Pot returns logs in various formats depending on the endpoint
        if isinstance(data, dict) and 'hits' in data and 'hits' in data['hits']:
            # Elasticsearch format
            for hit in data['hits']['hits']:
                source = hit.get('_source', {})
                log_entry = {
                    'timestamp': source.get('@timestamp', datetime.now().isoformat()),
                    'source_ip': source.get('src_ip', 'unknown'),
                    'destination_ip': source.get('dest_ip', 'unknown'),
                    'port': source.get('dest_port', 0),
                    'protocol': source.get('protocol', 'unknown'),
                    'attack_type': self._detect_attack_type(source),
                    'payload': source,
                    'severity': source.get('severity', 5),
                    'honeypot_service': source.get('honeypot', 't-pot')
                }
                logs.append(log_entry)
        
        elif isinstance(data, list):
            # Direct log array
            for entry in data:
                log_entry = {
                    'timestamp': entry.get('timestamp', datetime.now().isoformat()),
                    'source_ip': entry.get('src_ip', 'unknown'),
                    'destination_ip': entry.get('dest_ip', 'unknown'),
                    'port': entry.get('dest_port', 0),
                    'protocol': entry.get('protocol', 'unknown'),
                    'attack_type': self._detect_attack_type(entry),
                    'payload': entry,
                    'severity': entry.get('severity', 5),
                    'honeypot_service': entry.get('honeypot', 't-pot')
                }
                logs.append(log_entry)
        
        return logs
    
    async def _fetch_cowrie_logs(self) -> List[Dict[str, Any]]:
        """Fetch logs from Cowrie"""
        try:
            # Cowrie logs format
            url = f"{self.api_url.rstrip('/')}/api/logs/latest"
            
            async with aiohttp.ClientSession() as session:
                auth = None
                if self.username and self.password:
                    auth = aiohttp.BasicAuth(self.username, self.password)
                
                async with session.get(url, auth=auth, timeout=30) as response:
                    if response.status == 200:
                        data = await response.json()
                        return self._parse_cowrie_logs(data)
                    else:
                        logger.error(f"Failed to fetch Cowrie logs: {response.status}")
                        return []
        except Exception as e:
            logger.error(f"Error fetching Cowrie logs: {e}")
            return []
    
    def _parse_cowrie_logs(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Parse Cowrie log data"""
        logs = []
        
        if isinstance(data, list):
            for entry in data:
                log_entry = {
                    'timestamp': entry.get('timestamp', datetime.now().isoformat()),
                    'source_ip': entry.get('src_ip', entry.get('ip', 'unknown')),
                    'username': entry.get('username', ''),
                    'password': entry.get('password', ''),
                    'input': entry.get('input', ''),
                    'session': entry.get('session', ''),
                    'eventid': entry.get('eventid', ''),
                    'attack_type': 'brute_force' if entry.get('eventid') == 'cowrie.login.failed' else 'successful_login',
                    'severity': 6 if 'failed' in entry.get('eventid', '') else 3,
                    'honeypot_service': 'cowrie'
                }
                logs.append(log_entry)
        
        return logs
    
    async def _fetch_dionaea_logs(self) -> List[Dict[str, Any]]:
        """Fetch logs from Dionaea"""
        try:
            url = f"{self.api_url.rstrip('/')}/json"
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=30) as response:
                    if response.status == 200:
                        data = await response.json()
                        return self._parse_dionaea_logs(data)
                    else:
                        logger.error(f"Failed to fetch Dionaea logs: {response.status}")
                        return []
        except Exception as e:
            logger.error(f"Error fetching Dionaea logs: {e}")
            return []
    
    def _parse_dionaea_logs(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Parse Dionaea log data"""
        logs = []
        
        # Dionaea JSON log format
        if isinstance(data, dict):
            connections = data.get('connections', [])
            for conn in connections:
                log_entry = {
                    'timestamp': conn.get('timestamp', datetime.now().isoformat()),
                    'source_ip': conn.get('remote_host', 'unknown'),
                    'destination_ip': conn.get('local_host', 'unknown'),
                    'port': conn.get('remote_port', 0),
                    'protocol': conn.get('connection_type', 'unknown'),
                    'attack_type': 'malware' if conn.get('malware') else 'exploit',
                    'payload': conn,
                    'severity': 8 if conn.get('malware') else 6,
                    'honeypot_service': 'dionaea'
                }
                logs.append(log_entry)
        
        return logs
    
    async def _fetch_generic_logs(self) -> List[Dict[str, Any]]:
        """Fetch logs from generic honeypot"""
        try:
            url = self.api_url
            
            async with aiohttp.ClientSession() as session:
                headers = {'Accept': 'application/json'}
                if self.api_key:
                    headers['Authorization'] = f'Bearer {self.api_key}'
                
                async with session.get(url, headers=headers, timeout=30) as response:
                    if response.status == 200:
                        data = await response.json()
                        return self._parse_generic_logs(data)
                    else:
                        logger.error(f"Failed to fetch generic logs: {response.status}")
                        return []
        except Exception as e:
            logger.error(f"Error fetching generic logs: {e}")
            return []
    
    def _parse_generic_logs(self, data: Any) -> List[Dict[str, Any]]:
        """Parse generic log data"""
        logs = []
        
        if isinstance(data, list):
            for entry in data:
                log_entry = {
                    'timestamp': entry.get('timestamp', datetime.now().isoformat()),
                    'source_ip': entry.get('src_ip', entry.get('ip', 'unknown')),
                    'destination_ip': entry.get('dest_ip', entry.get('target', 'unknown')),
                    'port': entry.get('port', entry.get('dest_port', 0)),
                    'protocol': entry.get('protocol', 'unknown'),
                    'attack_type': self._detect_attack_type(entry),
                    'payload': entry,
                    'severity': entry.get('severity', 5),
                    'honeypot_service': self.name
                }
                logs.append(log_entry)
        
        return logs
    
    def _detect_attack_type(self, entry: Dict[str, Any]) -> str:
        """Detect attack type from log entry"""
        if isinstance(entry, dict):
            payload = json.dumps(entry).lower()
        else:
            payload = str(entry).lower()
        
        if any(keyword in payload for keyword in ['nmap', 'scan', 'portscan']):
            return 'port_scan'
        elif any(keyword in payload for keyword in ['password', 'login', 'brute', 'ssh']):
            return 'brute_force'
        elif any(keyword in payload for keyword in ['malware', 'virus', 'trojan', 'ransomware']):
            return 'malware'
        elif any(keyword in payload for keyword in ['ddos', 'flood', 'syn']):
            return 'ddos'
        elif any(keyword in payload for keyword in ['exploit', 'vulnerability', 'cve']):
            return 'exploit'
        elif any(keyword in payload for keyword in ['phish', 'credential', 'steal']):
            return 'phishing'
        else:
            return 'other'
    
    async def start_continuous_fetch(self):
        """Start continuous log fetching"""
        if self.is_running:
            logger.warning(f"Honeypot connector {self.name} is already running")
            return
        
        self.is_running = True
        self.status = HoneypotConnectionStatus.CONNECTED
        
        logger.info(f"Starting continuous fetch for {self.name}")
        
        while self.is_running:
            try:
                logs = await self.fetch_logs()
                if logs:
                    logger.info(f"Fetched {len(logs)} logs from {self.name}")
                    
                    # Process logs asynchronously
                    asyncio.create_task(self._process_fetched_logs(logs))
                
                # Wait before next fetch
                await asyncio.sleep(self.fetch_interval)
                
            except Exception as e:
                logger.error(f"Error in continuous fetch for {self.name}: {e}")
                self.status = HoneypotConnectionStatus.ERROR
                await asyncio.sleep(60)  # Wait longer on error
    
    async def stop_continuous_fetch(self):
        """Stop continuous log fetching"""
        self.is_running = False
        self.status = HoneypotConnectionStatus.DISCONNECTED
        logger.info(f"Stopped continuous fetch for {self.name}")
    
    async def _process_fetched_logs(self, logs: List[Dict[str, Any]]):
        """Process fetched logs"""
        try:
            # Here you can add processing logic:
            # 1. Save to database
            # 2. Trigger analysis
            # 3. Send alerts
            # 4. Update dashboard
            
            # For now, just log the processing
            logger.info(f"Processing {len(logs)} logs from {self.name}")
            
            # You can integrate with existing services
            # analyzer = ThreatAnalyzer(logs)
            # analysis = await analyzer.analyze()
            # logger.info(f"Analysis complete: {analysis.get('total_attacks', 0)} attacks detected")
            
        except Exception as e:
            logger.error(f"Error processing logs: {e}")
    
    def get_status(self) -> Dict[str, Any]:
        """Get connector status"""
        return {
            'connection_id': self.connection_id,
            'name': self.name,
            'honeypot_type': self.honeypot_type.value,
            'status': self.status.value,
            'last_fetch': self.last_fetch.isoformat() if self.last_fetch else None,
            'total_logs_fetched': self.total_logs_fetched,
            'is_running': self.is_running,
            'buffer_size': len(self.log_buffer)
        }
    
    def get_buffer(self, max_items: int = 100) -> List[Dict[str, Any]]:
        """Get logs from buffer"""
        return self.log_buffer[-max_items:] if self.log_buffer else []
    
    def clear_buffer(self):
        """Clear log buffer"""
        self.log_buffer = []
        logger.info(f"Cleared buffer for {self.name}")