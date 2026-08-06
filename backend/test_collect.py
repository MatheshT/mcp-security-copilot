import asyncio
from app.database import SessionLocal
from app.log_collector.windows_log_collector import WindowsLogCollector
from app.routes.log_analysis.api import save_logs_to_db

async def run():
    collector = WindowsLogCollector()
    db = SessionLocal()
    
    print('Collecting Windows Event Logs...')
    log_data = await collector.collect_specific_source('windows_event', 24)
    print(f'Collected {len(log_data.get("logs", []))} events.')
    save_logs_to_db(log_data, db)
    
    print('Collecting Sysmon Logs...')
    sysmon_data = await collector.collect_specific_source('sysmon', 24)
    print(f'Collected {len(sysmon_data.get("logs", []))} sysmon events.')
    save_logs_to_db(sysmon_data, db)
    
    print('Collecting Defender Logs...')
    defender_data = await collector.collect_specific_source('defender', 24)
    print(f'Collected {len(defender_data.get("logs", []))} defender events.')
    save_logs_to_db(defender_data, db)
    
    db.close()
    print("Done!")

if __name__ == "__main__":
    asyncio.run(run())
