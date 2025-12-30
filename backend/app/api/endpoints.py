from fastapi import APIRouter, UploadFile, File, Form, HTTPException, BackgroundTasks, Depends
from fastapi.responses import JSONResponse, FileResponse
from typing import Optional, List
import json
import asyncio
from sqlalchemy.orm import Session
from datetime import datetime

from app.models.schemas import *
from app.services.log_processor import LogProcessor
from app.services.threat_intelligence import ThreatAnalyzer
from app.services.stix_generator import STIXGenerator
from app.utils.file_handlers import save_uploaded_file
from app.models.database import get_db, UploadedFile, AnalysisResult, AttackLog, STIXReport

api_router = APIRouter()


# File Upload Endpoint - UPDATED VERSION
@api_router.post("/upload", response_model=APIResponse)
async def upload_log_file(
    file: UploadFile = File(...),
    honeypot_type: str = Form(...),
    description: Optional[str] = Form(None),
    db: Session = Depends(get_db)  # Add database session
):
    """Upload JSON log file for analysis"""
    try:
        print(f"DEBUG: Starting upload for file: {file.filename}")
        
        # Validate file
        if not file.filename.lower().endswith('.json'):
            raise HTTPException(400, "Only JSON files are supported")

        # Save file to filesystem
        file_path = await save_uploaded_file(file)
        print(f"DEBUG: File saved to: {file_path}")
        
        # Save file metadata to database FIRST
        uploaded_file = UploadedFile(
            filename=file.filename,
            honeypot_type=honeypot_type,
            description=description,
            file_size=file.size,
            content_type=file.content_type
        )
        db.add(uploaded_file)
        db.flush()  # Get the ID without committing
        print(f"DEBUG: File saved to database with ID: {uploaded_file.id}")

        # Process logs
        processor = LogProcessor(file_path, honeypot_type)
        processed_data = await processor.process()
        print(f"DEBUG: Processed {len(processed_data)} log entries")

        # Save attack logs to database (limit to 5000 for performance)
        attack_count = 0
        for attack in processed_data[:5000]:  # Limit for performance
            try:
                # Parse timestamp
                timestamp = attack.get('timestamp')
                if not timestamp:
                    timestamp = datetime.now()
                elif isinstance(timestamp, str):
                    try:
                        timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                    except:
                        timestamp = datetime.now()
                
                attack_log = AttackLog(
                    file_id=uploaded_file.id,
                    timestamp=timestamp,
                    source_ip=attack.get('source_ip', 'unknown'),
                    destination_ip=attack.get('destination_ip', 'unknown'),
                    port=attack.get('port'),
                    protocol=attack.get('protocol'),
                    attack_type=attack.get('attack_type', 'other'),
                    payload=attack.get('payload'),
                    severity=attack.get('severity', 5),
                    country=attack.get('country'),
                    city=attack.get('city')
                )
                db.add(attack_log)
                attack_count += 1
            except Exception as e:
                print(f"WARNING: Failed to save attack log: {e}")
                continue
        
        print(f"DEBUG: Saved {attack_count} attack logs to database")

        # Analyze threats
        analyzer = ThreatAnalyzer(processed_data)
        analysis = await analyzer.analyze()
        print(f"DEBUG: Analysis completed. Total attacks: {analysis.get('total_attacks', 0)}")
        
        # Save analysis results to database
        analysis_result = AnalysisResult(
            file_id=uploaded_file.id,
            total_attacks=analysis.get('total_attacks', 0),
            unique_attackers=analysis.get('unique_attackers', 0),
            attack_distribution=analysis.get('attack_distribution', {}),
            hourly_pattern=analysis.get('hourly_pattern', {}),
            average_severity=analysis.get('average_severity', 0),
            high_severity_attacks=analysis.get('high_severity_attacks', 0),
            mitre_techniques=analysis.get('mitre_techniques', {}),
            timeline_data=analysis.get('timeline', [])
        )
        db.add(analysis_result)
        db.flush()  # Get the analysis ID
        print(f"DEBUG: Analysis saved with ID: {analysis_result.id}")

        # Generate STIX
        stix_gen = STIXGenerator(
            analysis_data=analysis,
            processed_logs=processed_data
        )
        stix_bundle = stix_gen.generate_bundle()
        
        # Save STIX report to database
        stix_report = STIXReport(
            analysis_id=analysis_result.id,
            stix_bundle=stix_bundle
        )
        db.add(stix_report)
        
        # Commit all database changes
        db.commit()
        print(f"DEBUG: All data committed to database")
        
        # Refresh to get all IDs
        db.refresh(uploaded_file)
        db.refresh(analysis_result)
        db.refresh(stix_report)

        return APIResponse(
            success=True,
            message="File uploaded and analyzed successfully",
            data={
                "analysis": analysis,
                "stix_bundle": stix_bundle,
                "file_info": {
                    "filename": file.filename,
                    "size": file.size,
                    "content_type": file.content_type,
                    "file_id": uploaded_file.id,
                    "analysis_id": analysis_result.id,
                    "stix_report_id": stix_report.id,
                    "saved_path": file_path,  # Include the file path
                    "attack_logs_saved": attack_count
                }
            }
        )

    except Exception as e:
        db.rollback()  # Rollback on error
        print(f"ERROR: Upload failed: {str(e)}")
        import traceback
        print(f"ERROR traceback: {traceback.format_exc()}")
        raise HTTPException(500, f"Error processing file: {str(e)}")

# Add endpoints to retrieve data from database

@api_router.get("/uploads")
async def get_uploaded_files(
    db: Session = Depends(get_db),
    skip: int = 0,
    limit: int = 10
):
    """Get list of uploaded files"""
    files = db.query(UploadedFile).order_by(UploadedFile.uploaded_at.desc()).offset(skip).limit(limit).all()
    
    return {
        "files": [
            {
                "id": file.id,
                "filename": file.filename,
                "honeypot_type": file.honeypot_type,
                "description": file.description,
                "uploaded_at": file.uploaded_at.isoformat(),
                "file_size": file.file_size,
                "has_analysis": file.analysis is not None
            }
            for file in files
        ],
        "total": db.query(UploadedFile).count()
    }

@api_router.get("/uploads/{file_id}/analysis")
async def get_file_analysis(
    file_id: int,
    db: Session = Depends(get_db)
):
    """Get analysis for a specific uploaded file"""
    file = db.query(UploadedFile).filter(UploadedFile.id == file_id).first()
    
    if not file:
        raise HTTPException(404, "File not found")
    
    if not file.analysis:
        raise HTTPException(404, "No analysis found for this file")
    
    return {
        "file_id": file.id,
        "filename": file.filename,
        "analysis": {
            "total_attacks": file.analysis.total_attacks,
            "unique_attackers": file.analysis.unique_attackers,
            "attack_distribution": file.analysis.attack_distribution,
            "average_severity": file.analysis.average_severity,
            "high_severity_attacks": file.analysis.high_severity_attacks,
            "mitre_techniques": file.analysis.mitre_techniques,
            "analyzed_at": file.analysis.analyzed_at.isoformat()
        },
        "attack_logs_count": db.query(AttackLog).filter(AttackLog.file_id == file_id).count(),
        "has_stix_report": len(file.analysis.stix_reports) > 0
    }

@api_router.get("/uploads/{file_id}/stix")
async def get_file_stix_report(
    file_id: int,
    db: Session = Depends(get_db)
):
    """Get STIX report for a specific uploaded file"""
    file = db.query(UploadedFile).filter(UploadedFile.id == file_id).first()
    
    if not file:
        raise HTTPException(404, "File not found")
    
    if not file.analysis or not file.analysis.stix_reports:
        raise HTTPException(404, "No STIX report found for this file")
    
    stix_report = file.analysis.stix_reports[0]  # Get first STIX report
    
    return {
        "file_id": file.id,
        "filename": file.filename,
        "stix_report": {
            "id": stix_report.id,
            "generated_at": stix_report.generated_at.isoformat(),
            "stix_bundle": stix_report.stix_bundle
        }
    }

@api_router.get("/uploads/{file_id}/attack-logs")
async def get_file_attack_logs(
    file_id: int,
    db: Session = Depends(get_db),
    skip: int = 0,
    limit: int = 100
):
    """Get attack logs for a specific uploaded file"""
    file = db.query(UploadedFile).filter(UploadedFile.id == file_id).first()
    
    if not file:
        raise HTTPException(404, "File not found")
    
    attack_logs = db.query(AttackLog).filter(AttackLog.file_id == file_id)\
        .order_by(AttackLog.timestamp.desc())\
        .offset(skip).limit(limit).all()
    
    return {
        "file_id": file.id,
        "filename": file.filename,
        "attack_logs": [
            {
                "id": log.id,
                "timestamp": log.timestamp.isoformat(),
                "source_ip": log.source_ip,
                "destination_ip": log.destination_ip,
                "port": log.port,
                "protocol": log.protocol,
                "attack_type": log.attack_type,
                "severity": log.severity,
                "country": log.country,
                "city": log.city
            }
            for log in attack_logs
        ],
        "total": db.query(AttackLog).filter(AttackLog.file_id == file_id).count(),
        "skip": skip,
        "limit": limit
    }

# Honeypot Connection Endpoint
@api_router.post("/connect", response_model=APIResponse)
async def connect_honeypot(
    connection: HoneypotConnection,
    background_tasks: BackgroundTasks
):
    """Connect to live honeypot and fetch logs"""
    try:
        connector = HoneypotConnector(connection)

        # Test connection
        if not await connector.test_connection():
            raise HTTPException(400, "Failed to connect to honeypot")

        # Fetch logs in background
        background_tasks.add_task(connector.fetch_logs_continuous)

        return APIResponse(
            success=True,
            message=f"Successfully connected to {connection.name}",
            data={"connection_id": connector.connection_id}
        )

    except Exception as e:
        raise HTTPException(500, f"Connection error: {str(e)}")

# Analysis Endpoints
@api_router.post("/analyze", response_model=AnalysisResponse)
async def analyze_logs(
    request: AnalysisRequest,
    db: Session = Depends(get_db)
):
    """Analyze logs based on criteria from database"""
    try:
        # Get attack logs from database based on criteria
        query = db.query(AttackLog)
        
        # Apply filters
        if request.start_date:
            query = query.filter(AttackLog.timestamp >= request.start_date)
        if request.end_date:
            query = query.filter(AttackLog.timestamp <= request.end_date)
        if request.attack_types:
            query = query.filter(AttackLog.attack_type.in_(request.attack_types))
        if request.min_severity:
            query = query.filter(AttackLog.severity >= request.min_severity)
        
        attack_logs = query.all()
        
        # Convert to format expected by ThreatAnalyzer
        processed_data = [
            {
                'timestamp': log.timestamp,
                'source_ip': log.source_ip,
                'destination_ip': log.destination_ip,
                'port': log.port,
                'protocol': log.protocol,
                'attack_type': log.attack_type,
                'payload': log.payload,
                'severity': log.severity,
                'country': log.country,
                'city': log.city
            }
            for log in attack_logs
        ]
        
        # Analyze threats
        analyzer = ThreatAnalyzer(processed_data)
        analysis = await analyzer.analyze()
        
        return AnalysisResponse(
            total_attacks=analysis.get('total_attacks', 0),
            unique_attackers=analysis.get('unique_attackers', 0),
            attack_distribution=analysis.get('attack_distribution', {}),
            timeline_data=analysis.get('timeline', []),
            top_countries=[],  # You can add country analysis
            mitre_coverage=analysis.get('mitre_techniques', {})
        )
    except Exception as e:
        raise HTTPException(500, f"Analysis error: {str(e)}")

@api_router.get("/dashboard/stats")
async def get_dashboard_stats(db: Session = Depends(get_db)):
    """Get dashboard statistics from database"""
    try:
        print(f"DEBUG: Fetching dashboard stats from database")
        
        # Get total stats
        total_files = db.query(UploadedFile).count()
        
        if total_files == 0:
            print(f"DEBUG: No files in database, returning empty stats")
            return {
                "total_files": 0,
                "total_attacks": 0,
                "unique_attackers": 0,
                "high_severity_attacks": 0,
                "average_severity": 0,
                "current_threat_level": "Low",
                "attack_distribution": {},
                "mitre_techniques": {},
                "recent_uploads": []
            }
        
        # Get aggregated stats
        from sqlalchemy import func
        
        total_attacks = db.query(func.sum(AnalysisResult.total_attacks)).scalar() or 0
        unique_attackers = db.query(func.sum(AnalysisResult.unique_attackers)).scalar() or 0
        high_severity_attacks = db.query(func.sum(AnalysisResult.high_severity_attacks)).scalar() or 0
        
        # Calculate average severity
        avg_severity_result = db.query(func.avg(AnalysisResult.average_severity)).scalar()
        average_severity = round(float(avg_severity_result or 0), 2)
        
        # Get all attack distributions
        all_attack_dist = {}
        all_mitre_tech = {}
        
        analysis_results = db.query(AnalysisResult).all()
        for analysis in analysis_results:
            if analysis.attack_distribution:
                for attack_type, count in analysis.attack_distribution.items():
                    all_attack_dist[attack_type] = all_attack_dist.get(attack_type, 0) + count
            
            if analysis.mitre_techniques:
                for tech, count in analysis.mitre_techniques.items():
                    all_mitre_tech[tech] = all_mitre_tech.get(tech, 0) + count
        
        # Get recent uploads
        recent_uploads = db.query(UploadedFile).order_by(UploadedFile.uploaded_at.desc()).limit(5).all()
        
        # Determine threat level
        threat_level = "Low"
        if high_severity_attacks > 100:
            threat_level = "High"
        elif high_severity_attacks > 20:
            threat_level = "Medium"
        
        print(f"DEBUG: Returning stats: {total_files} files, {total_attacks} attacks")
        
        return {
            "total_files": total_files,
            "total_attacks": total_attacks,
            "unique_attackers": unique_attackers,
            "high_severity_attacks": high_severity_attacks,
            "average_severity": average_severity,
            "current_threat_level": threat_level,
            "attack_distribution": all_attack_dist,
            "mitre_techniques": all_mitre_tech,
            "recent_uploads": [
                {
                    "id": upload.id,
                    "filename": upload.filename,
                    "honeypot_type": upload.honeypot_type,
                    "uploaded_at": upload.uploaded_at.isoformat(),
                    "description": upload.description
                }
                for upload in recent_uploads
            ]
        }
    except Exception as e:
        print(f"ERROR: Failed to get dashboard stats: {str(e)}")
        import traceback
        print(f"ERROR traceback: {traceback.format_exc()}")
        raise HTTPException(500, f"Error fetching stats: {str(e)}")

#  STIX generation endpoint
@api_router.post("/stix/generate")
async def generate_stix_report(request: STIXGenerationRequest, db: Session = Depends(get_db)):
    """Generate STIX report for specific attacks or files"""
    try:
        print(f"DEBUG: STIX generation request: {request}")
        
        if request.file_id:
            # Generate STIX for specific file
            file = db.query(UploadedFile).filter(UploadedFile.id == request.file_id).first()
            if not file:
                raise HTTPException(404, "File not found")
            
            if not file.analysis or not file.analysis.stix_reports:
                raise HTTPException(404, "No STIX report found for this file")
            
            # Return existing STIX report
            stix_report = file.analysis.stix_reports[0]
            return {
                "success": True,
                "stix_bundle": stix_report.stix_bundle
            }
        
        elif request.attack_ids:
            # Generate STIX for specific attack IDs
            # Get attack logs for these IDs
            attack_logs = db.query(AttackLog).filter(AttackLog.id.in_(request.attack_ids)).all()
            
            if not attack_logs:
                raise HTTPException(404, "No attacks found with the provided IDs")
            
            # Convert to format expected by STIXGenerator
            processed_data = [
                {
                    'timestamp': log.timestamp,
                    'source_ip': log.source_ip,
                    'destination_ip': log.destination_ip,
                    'port': log.port,
                    'protocol': log.protocol,
                    'attack_type': log.attack_type,
                    'payload': log.payload,
                    'severity': log.severity,
                    'country': log.country,
                    'city': log.city
                }
                for log in attack_logs
            ]
            
            # Generate STIX
            stix_gen = STIXGenerator(processed_logs=processed_data)
            stix_bundle = stix_gen.generate_bundle()
            
            return {
                "success": True,
                "stix_bundle": stix_bundle
            }
        
        elif request.all_attacks:
            # Generate STIX for all attacks in database
            attack_logs = db.query(AttackLog).limit(1000).all()  # Limit for performance
            
            processed_data = [
                {
                    'timestamp': log.timestamp,
                    'source_ip': log.source_ip,
                    'destination_ip': log.destination_ip,
                    'port': log.port,
                    'protocol': log.protocol,
                    'attack_type': log.attack_type,
                    'payload': log.payload,
                    'severity': log.severity,
                    'country': log.country,
                    'city': log.city
                }
                for log in attack_logs
            ]
            
            stix_gen = STIXGenerator(processed_logs=processed_data)
            stix_bundle = stix_gen.generate_bundle()
            
            return {
                "success": True,
                "stix_bundle": stix_bundle
            }
        
        else:
            # Default: generate from recent attacks
            recent_attacks = db.query(AttackLog).order_by(AttackLog.timestamp.desc()).limit(100).all()
            
            processed_data = [
                {
                    'timestamp': log.timestamp,
                    'source_ip': log.source_ip,
                    'destination_ip': log.destination_ip,
                    'port': log.port,
                    'protocol': log.protocol,
                    'attack_type': log.attack_type,
                    'payload': log.payload,
                    'severity': log.severity,
                    'country': log.country,
                    'city': log.city
                }
                for log in recent_attacks
            ]
            
            stix_gen = STIXGenerator(processed_logs=processed_data)
            stix_bundle = stix_gen.generate_bundle()
            
            return {
                "success": True,
                "stix_bundle": stix_bundle
            }
            
    except Exception as e:
        print(f"ERROR: STIX generation error: {str(e)}")
        raise HTTPException(500, f"STIX generation error: {str(e)}")

# MITRE ATT&CK Mapping
@api_router.get("/mitre/map/{attack_id}")
async def map_to_mitre(attack_id: str):
    """Map attack to MITRE ATT&CK framework"""
    try:
        analyzer = ThreatAnalyzer()
        mapping = await analyzer.map_to_mitre(attack_id)
        return mapping
    except Exception as e:
        raise HTTPException(500, f"MITRE mapping error: {str(e)}")

# Download Reports
@api_router.get("/report/download/{report_type}")
async def download_report(report_type: str):
    """Download analysis report"""
    try:
        if report_type == "stix":
            generator = STIXGenerator()
            report_path = generator.generate_report_file()
            return FileResponse(
                report_path,
                filename="stix_report.json",
                media_type="application/json"
            )
        elif report_type == "csv":
            # Generate CSV report
            pass
        else:
            raise HTTPException(400, "Invalid report type")

    except Exception as e:
        raise HTTPException(500, f"Report generation error: {str(e)}")

        