import json
import pandas as pd
from datetime import datetime
from typing import Dict, List, Any, Optional
import asyncio
import aiofiles
import logging

logger = logging.getLogger(__name__)

class LogProcessor:
    def __init__(self, file_path: str, honeypot_type: str):
        self.file_path = file_path
        self.honeypot_type = honeypot_type.lower()
        
    async def process(self) -> List[Dict[str, Any]]:
        """Process log file and extract attack patterns"""
        
        try:
            async with aiofiles.open(self.file_path, 'r') as f:
                content = await f.read()
                
            # Handle different honeypot types
            if self.honeypot_type == 'cowrie':
                return await self._process_cowrie_logs(content)
            elif self.honeypot_type == 't-pot':
                return await self._process_tpot_logs(content)
            else:
                # Try generic processing
                return await self._process_generic_logs(content)
                
        except Exception as e:
            logger.error(f"Error processing file: {e}")
            raise Exception(f"Error processing file: {str(e)}")
    
    async def _process_cowrie_logs(self, content: str) -> List[Dict[str, Any]]:
        """Process Cowrie JSON logs"""
        processed_logs = []
        lines = content.strip().split('\n')
        
        session_data = {}  # Track sessions for correlation
        
        for line in lines:
            if not line.strip():
                continue
                
            try:
                log_entry = json.loads(line)
                eventid = log_entry.get('eventid', '')
                
                # Process based on event type
                if eventid == 'cowrie.session.connect':
                    processed_log = self._parse_cowrie_connect(log_entry)
                    if processed_log:
                        session_id = log_entry.get('session', '')
                        session_data[session_id] = {
                            'start_time': log_entry.get('timestamp'),
                            'src_ip': log_entry.get('src_ip'),
                            'dst_ip': log_entry.get('dst_ip'),
                            'dst_port': log_entry.get('dst_port', 22),
                            'events': []
                        }
                        processed_logs.append(processed_log)
                        
                elif eventid == 'cowrie.login.failed':
                    processed_log = self._parse_cowrie_login_failed(log_entry)
                    if processed_log:
                        processed_logs.append(processed_log)
                        
                elif eventid == 'cowrie.login.success':
                    processed_log = self._parse_cowrie_login_success(log_entry)
                    if processed_log:
                        processed_logs.append(processed_log)
                        
                elif eventid == 'cowrie.command.input':
                    processed_log = self._parse_cowrie_command(log_entry)
                    if processed_log:
                        processed_logs.append(processed_log)
                        
                elif eventid in ['cowrie.session.closed', 'cowrie.session.file_download']:
                    # Process other relevant events
                    processed_log = self._parse_cowrie_general(log_entry)
                    if processed_log:
                        processed_logs.append(processed_log)
                        
            except json.JSONDecodeError as e:
                logger.warning(f"Failed to parse JSON line: {e}")
                continue
            except Exception as e:
                logger.warning(f"Error processing line: {e}")
                continue
        
        return processed_logs
    
    def _parse_cowrie_connect(self, log_entry: Dict[str, Any]) -> Dict[str, Any]:
        """Parse Cowrie connection event"""
        timestamp = self._parse_timestamp(log_entry.get('timestamp'))
        
        return {
            "timestamp": timestamp,
            "source_ip": log_entry.get('src_ip', 'unknown'),
            "destination_ip": log_entry.get('dst_ip', 'unknown'),
            "port": log_entry.get('dst_port', 22),
            "protocol": log_entry.get('protocol', 'ssh').upper(),
            "attack_type": "connection_attempt",
            "payload": {
                "event": "connect",
                "src_port": log_entry.get('src_port'),
                "session": log_entry.get('session', ''),
                "message": log_entry.get('message', '')
            },
            "severity": 3,  # Low severity for just connection
            "country": None,
            "city": None,
            "original_data": log_entry
        }
    
    def _parse_cowrie_login_failed(self, log_entry: Dict[str, Any]) -> Dict[str, Any]:
        """Parse Cowrie failed login event"""
        timestamp = self._parse_timestamp(log_entry.get('timestamp'))
        
        return {
            "timestamp": timestamp,
            "source_ip": log_entry.get('src_ip', 'unknown'),
            "destination_ip": "unknown",  # Cowrie doesn't always have dst_ip in login events
            "port": 22,  # Default SSH port
            "protocol": "SSH",
            "attack_type": "brute_force",
            "payload": {
                "event": "login_failed",
                "username": log_entry.get('username', ''),
                "password": log_entry.get('password', ''),
                "session": log_entry.get('session', ''),
                "message": log_entry.get('message', '')
            },
            "severity": 6,  # Medium severity for brute force
            "country": None,
            "city": None,
            "original_data": log_entry
        }
    
    def _parse_cowrie_login_success(self, log_entry: Dict[str, Any]) -> Dict[str, Any]:
        """Parse Cowrie successful login event"""
        timestamp = self._parse_timestamp(log_entry.get('timestamp'))
        
        return {
            "timestamp": timestamp,
            "source_ip": log_entry.get('src_ip', 'unknown'),
            "destination_ip": "unknown",
            "port": 22,
            "protocol": "SSH",
            "attack_type": "credential_theft",
            "payload": {
                "event": "login_success",
                "username": log_entry.get('username', ''),
                "password": log_entry.get('password', ''),
                "session": log_entry.get('session', ''),
                "message": log_entry.get('message', '')
            },
            "severity": 8,  # High severity - successful compromise
            "country": None,
            "city": None,
            "original_data": log_entry
        }
    
    def _parse_cowrie_command(self, log_entry: Dict[str, Any]) -> Dict[str, Any]:
        """Parse Cowrie command execution event"""
        timestamp = self._parse_timestamp(log_entry.get('timestamp'))
        command = log_entry.get('input', '').lower()
        
        # Determine attack type based on command
        attack_type = "command_execution"
        if any(cmd in command for cmd in ['wget', 'curl', 'download']):
            attack_type = "malware_download"
        elif any(cmd in command for cmd in ['rm ', 'delete', 'format']):
            attack_type = "destructive_command"
        elif any(cmd in command for cmd in ['cat ', 'more ', 'less ', 'view ']):
            attack_type = "data_exfiltration"
        
        return {
            "timestamp": timestamp,
            "source_ip": log_entry.get('src_ip', 'unknown'),
            "destination_ip": "unknown",
            "port": 22,
            "protocol": "SSH",
            "attack_type": attack_type,
            "payload": {
                "event": "command_input",
                "command": log_entry.get('input', ''),
                "session": log_entry.get('session', ''),
                "message": log_entry.get('message', '')
            },
            "severity": 7 if attack_type == "command_execution" else 9,
            "country": None,
            "city": None,
            "original_data": log_entry
        }
    
    def _parse_cowrie_general(self, log_entry: Dict[str, Any]) -> Dict[str, Any]:
        """Parse general Cowrie events"""
        timestamp = self._parse_timestamp(log_entry.get('timestamp'))
        eventid = log_entry.get('eventid', '')
        
        if eventid == 'cowrie.session.closed':
            attack_type = "session_closed"
            severity = 2
        elif eventid == 'cowrie.session.file_download':
            attack_type = "file_download"
            severity = 8
        else:
            attack_type = "other"
            severity = 3
        
        return {
            "timestamp": timestamp,
            "source_ip": log_entry.get('src_ip', 'unknown'),
            "destination_ip": "unknown",
            "port": 22,
            "protocol": "SSH",
            "attack_type": attack_type,
            "payload": log_entry,
            "severity": severity,
            "country": None,
            "city": None,
            "original_data": log_entry
        }
    
    async def _process_tpot_logs(self, content: str) -> List[Dict[str, Any]]:
        """Process T-Pot logs"""
        # For now, use generic processing
        return await self._process_generic_logs(content)
    
    async def _process_generic_logs(self, content: str) -> List[Dict[str, Any]]:
        """Process generic log format"""
        try:
            # Try to parse as JSON
            data = json.loads(content)
            
            if isinstance(data, dict) and 'logs' in data:
                # Structured format
                return self._process_structured_logs(data)
            elif isinstance(data, list):
                # Array format
                processed_logs = []
                for log_entry in data:
                    try:
                        processed_log = self._parse_generic_entry(log_entry)
                        if processed_log:
                            processed_logs.append(processed_log)
                    except Exception as e:
                        logger.warning(f"Failed to parse entry: {e}")
                return processed_logs
            else:
                # Try JSON lines
                return await self._process_json_lines(content)
                
        except json.JSONDecodeError:
            # Try JSON lines
            return await self._process_json_lines(content)
        except Exception as e:
            logger.error(f"Error processing generic logs: {e}")
            return []
    
    async def _process_json_lines(self, content: str) -> List[Dict[str, Any]]:
        """Process JSON lines format"""
        lines = content.strip().split('\n')
        processed_logs = []
        
        for line in lines:
            if not line.strip():
                continue
                
            try:
                log_entry = json.loads(line)
                processed_log = self._parse_generic_entry(log_entry)
                if processed_log:
                    processed_logs.append(processed_log)
            except json.JSONDecodeError:
                # Skip non-JSON lines
                continue
            except Exception as e:
                logger.warning(f"Failed to parse line: {e}")
                continue
        
        return processed_logs
    
    def _parse_generic_entry(self, log_entry: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Parse generic log entry"""
        try:
            timestamp = self._parse_timestamp(log_entry.get('timestamp'))
            
            # Try to extract IPs
            source_ip = log_entry.get('src_ip') or log_entry.get('source_ip') or log_entry.get('ip') or 'unknown'
            dest_ip = log_entry.get('dst_ip') or log_entry.get('destination_ip') or log_entry.get('dest_ip') or 'unknown'
            
            # Determine attack type
            attack_type = self._detect_attack_type(log_entry)
            
            # Determine severity
            severity = self._calculate_severity_from_entry(log_entry, attack_type)
            
            # Determine protocol and port
            protocol = log_entry.get('protocol', 'UNKNOWN').upper()
            port = log_entry.get('dst_port') or log_entry.get('port') or self._get_port_from_protocol(protocol)
            
            return {
                "timestamp": timestamp,
                "source_ip": source_ip,
                "destination_ip": dest_ip,
                "port": port,
                "protocol": protocol,
                "attack_type": attack_type,
                "payload": log_entry,
                "severity": severity,
                "country": None,
                "city": None,
                "original_data": log_entry
            }
        except Exception as e:
            logger.warning(f"Failed to parse generic entry: {e}")
            return None
    
    def _parse_timestamp(self, timestamp_str: str) -> datetime:
        """Parse timestamp string to datetime"""
        if not timestamp_str:
            return datetime.now()
        
        try:
            # Handle various timestamp formats
            formats = [
                "%Y-%m-%dT%H:%M:%S.%fZ",
                "%Y-%m-%dT%H:%M:%SZ",
                "%Y-%m-%d %H:%M:%S",
                "%Y-%m-%d %H:%M:%S.%f"
            ]
            
            for fmt in formats:
                try:
                    return datetime.strptime(timestamp_str, fmt)
                except ValueError:
                    continue
            
            # If all formats fail, return current time
            return datetime.now()
        except:
            return datetime.now()
    
    def _detect_attack_type(self, log_entry: Dict[str, Any]) -> str:
        """Detect attack type from log entry"""
        eventid = str(log_entry.get('eventid', '')).lower()
        message = str(log_entry.get('message', '')).lower()
        
        # Check for Cowrie events
        if 'login.failed' in eventid:
            return 'brute_force'
        elif 'login.success' in eventid:
            return 'credential_theft'
        elif 'command.input' in eventid:
            return 'command_execution'
        elif 'session.connect' in eventid:
            return 'connection_attempt'
        elif 'session.closed' in eventid:
            return 'session_closed'
        elif 'file_download' in eventid:
            return 'malware_download'
        
        # Check message/content
        content = json.dumps(log_entry).lower()
        
        if any(keyword in content for keyword in ['nmap', 'scan', 'portscan']):
            return 'port_scan'
        elif any(keyword in content for keyword in ['password', 'login', 'brute', 'ssh']):
            return 'brute_force'
        elif any(keyword in content for keyword in ['malware', 'virus', 'trojan', 'ransomware']):
            return 'malware'
        elif any(keyword in content for keyword in ['ddos', 'flood', 'syn']):
            return 'ddos'
        elif any(keyword in content for keyword in ['exploit', 'vulnerability', 'cve']):
            return 'exploit'
        elif any(keyword in content for keyword in ['phish', 'credential', 'steal']):
            return 'phishing'
        elif any(keyword in content for keyword in ['sql', 'injection', 'select', 'union']):
            return 'sql_injection'
        elif any(keyword in content for keyword in ['xss', 'script', 'javascript']):
            return 'xss'
        else:
            return 'other'
    
    def _calculate_severity_from_entry(self, log_entry: Dict[str, Any], attack_type: str) -> int:
        """Calculate severity based on log entry and attack type"""
        severity_map = {
            'brute_force': 6,
            'credential_theft': 8,
            'malware': 9,
            'ddos': 8,
            'exploit': 7,
            'command_execution': 7,
            'malware_download': 9,
            'destructive_command': 9,
            'data_exfiltration': 8,
            'port_scan': 4,
            'connection_attempt': 3,
            'session_closed': 2,
            'other': 5
        }
        
        return severity_map.get(attack_type, 5)
    
    def _get_port_from_protocol(self, protocol: str) -> int:
        """Get default port from protocol"""
        port_mapping = {
            'SSH': 22,
            'HTTP': 80,
            'HTTPS': 443,
            'FTP': 21,
            'TELNET': 23,
            'SMTP': 25,
            'DNS': 53,
            'DHCP': 67,
            'TFTP': 69,
            'HTTP-PROXY': 8080,
            'MYSQL': 3306,
            'POSTGRESQL': 5432,
            'RDP': 3389,
            'VNC': 5900,
            'SNMP': 161
        }
        
        protocol_upper = protocol.upper()
        return port_mapping.get(protocol_upper, 0)