from pydantic import BaseModel
from datetime import datetime

class SecurityLog(BaseModel):
    id: str
    timestamp: datetime
    event_type: str
    severity: str
    description: str 