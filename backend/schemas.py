from pydantic import BaseModel, EmailStr
from pydantic import validator
VALID_STATES = [
    "AL", "AK", "AZ", "CA", "NY", "TX", "WA", "FL", "IL", "GA"
]
from datetime import datetime
from typing import Optional

class UserCreate(BaseModel):
    email: EmailStr
    full_name: str
    password: str

class UserResponse(BaseModel):
    id: int
    email: str
    full_name: str
    is_active: bool
    is_cpa: bool
    created_at: datetime

    class Config:
        from_attributes = True

class DocumentResponse(BaseModel):
    id: int
    filename: str
    file_type: str
    uploaded_at: datetime

    class Config:
        from_attributes = True

class TaxReturnCreate(BaseModel):
    tax_year: int
    income: float
    deductions: Optional[float] = None
    withholdings: float = 0
    marital_status: str  # NEW
    state: str  # NEW

    @validator('state')
    def validate_state(cls, v):
        if v not in VALID_STATES:
            raise ValueError('Invalid state')
        return v

class TaxReturnResponse(BaseModel):
    id: int
    tax_year: int
    income: float
    deductions: float
    withholdings: float
    marital_status: str  # NEW
    state: str  # NEW
    tax_owed: float
    refund_amount: float
    amount_owed: float
    status: str
    created_at: datetime

    class Config:
        from_attributes = True

class PaymentCreate(BaseModel):
    tax_return_id: int
    amount: float

class PaymentResponse(BaseModel):
    id: int
    amount: float
    payment_method: str
    status: str
    created_at: datetime

    class Config:
        from_attributes = True
