from fastapi import FastAPI, Depends, HTTPException, status, UploadFile, File
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
from typing import Optional
import jwt
from passlib.context import CryptContext
import uvicorn
import os
import logging

from database import SessionLocal, engine, Base
from models import User, Document, TaxReturn, Payment
from schemas import UserCreate, UserResponse, DocumentResponse, TaxReturnCreate, TaxReturnResponse, PaymentCreate, PaymentResponse

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create tables IMMEDIATELY when module loads
try:
    logger.info("Creating database tables...")
    Base.metadata.create_all(bind=engine)
    logger.info("Database tables created successfully!")
    
    # Test database connection
    db = SessionLocal()
    try:
        db.execute("SELECT 1")
        logger.info("Database connection successful!")
    except Exception as e:
        logger.error(f"Database connection failed: {e}")
    finally:
        db.close()
        
except Exception as e:
    logger.error(f"Database setup error: {e}")

app = FastAPI(title="TaxBox.AI API", version="1.0.0")

# CORS middleware - Updated for production
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "https://your-frontend-domain.com",
        "https://*.railway.app",
        "*"  # Allow all origins for now
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security - Using environment variables
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-change-in-production")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Database dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Health check endpoint for Railway
@app.get("/")
def health_check():
    return {"status": "healthy", "message": "TaxBox.AI API is running"}

# Auth functions
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except jwt.PyJWTError:
        raise credentials_exception
    user = db.query(User).filter(User.email == username).first()
    if user is None:
        raise credentials_exception
    return user

# Routes
@app.post("/register", response_model=UserResponse)
def register(user: UserCreate, db: Session = Depends(get_db)):
    try:
        logger.info(f"Registration attempt for email: {user.email}")
        
        # Check if user already exists
        db_user = db.query(User).filter(User.email == user.email).first()
        if db_user:
            logger.warning(f"Email already registered: {user.email}")
            raise HTTPException(status_code=400, detail="Email already registered")

        # Hash password
        hashed_password = get_password_hash(user.password)
        logger.info("Password hashed successfully")
        
        # Create user
        db_user = User(
            email=user.email,
            full_name=user.full_name,
            hashed_password=hashed_password
        )
        
        db.add(db_user)
        db.commit()
        db.refresh(db_user)
        
        logger.info(f"User created successfully: {user.email}")
        return db_user
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Registration error: {e}")
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Registration failed: {str(e)}")

@app.post("/token")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    try:
        user = db.query(User).filter(User.email == form_data.username).first()
        if not user or not verify_password(form_data.password, user.hashed_password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect email or password",
                headers={"WWW-Authenticate": "Bearer"},
            )
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": user.email}, expires_delta=access_token_expires
        )
        return {"access_token": access_token, "token_type": "bearer"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Login error: {e}")
        raise HTTPException(status_code=500, detail="Login failed")

@app.get("/users/me", response_model=UserResponse)
def read_users_me(current_user: User = Depends(get_current_user)):
    return current_user

@app.post("/documents/upload", response_model=DocumentResponse)
def upload_document(
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    try:
        # Create uploads directory if it doesn't exist
        os.makedirs("uploads", exist_ok=True)
        
        # In production, save to cloud storage (S3, etc.)
        file_path = f"uploads/{current_user.id}_{file.filename}"
        
        # Save file to disk (for now)
        with open(file_path, "wb") as buffer:
            content = file.file.read()
            buffer.write(content)

        db_document = Document(
            user_id=current_user.id,
            filename=file.filename,
            file_path=file_path,
            file_type=file.content_type
        )
        db.add(db_document)
        db.commit()
        db.refresh(db_document)
        return db_document
    except Exception as e:
        logger.error(f"Document upload error: {e}")
        raise HTTPException(status_code=500, detail="Document upload failed")

@app.get("/documents")
def get_documents(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return db.query(Document).filter(Document.user_id == current_user.id).all()

@app.post("/tax-returns", response_model=TaxReturnResponse)
def create_tax_return(
    tax_return: TaxReturnCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    try:
        # Basic tax calculation (simplified)
        total_income = tax_return.income
        deductions = tax_return.deductions or 12550  # Standard deduction 2023
        taxable_income = max(0, total_income - deductions)

        # Simplified tax calculation
        if taxable_income <= 10275:
            tax_owed = taxable_income * 0.10
        elif taxable_income <= 41775:
            tax_owed = 1027.50 + (taxable_income - 10275) * 0.12
        else:
            tax_owed = 4807.50 + (taxable_income - 41775) * 0.22

        refund_amount = max(0, tax_return.withholdings - tax_owed)
        amount_owed = max(0, tax_owed - tax_return.withholdings)

        db_tax_return = TaxReturn(
            user_id=current_user.id,
            tax_year=tax_return.tax_year,
            income=tax_return.income,
            deductions=deductions,
            withholdings=tax_return.withholdings,
            marital_status=tax_return.marital_status,
            state=tax_return.state,
            tax_owed=tax_owed,
            refund_amount=refund_amount,
            amount_owed=amount_owed,
            status="draft"
        )
        db.add(db_tax_return)
        db.commit()
        db.refresh(db_tax_return)
        return db_tax_return
    except Exception as e:
        logger.error(f"Tax return creation error: {e}")
        raise HTTPException(status_code=500, detail="Tax return creation failed")

@app.get("/tax-returns")
def get_tax_returns(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return db.query(TaxReturn).filter(TaxReturn.user_id == current_user.id).all()

@app.post("/payments", response_model=PaymentResponse)
def create_payment(
    payment: PaymentCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    try:
        # Payment stub - in production, integrate with Stripe/PayPal
        db_payment = Payment(
            user_id=current_user.id,
            tax_return_id=payment.tax_return_id,
            amount=payment.amount,
            payment_method="credit_card",
            status="completed"  # Stub - always successful
        )
        db.add(db_payment)
        db.commit()
        db.refresh(db_payment)
        return db_payment
    except Exception as e:
        logger.error(f"Payment creation error: {e}")
        raise HTTPException(status_code=500, detail="Payment creation failed")

# Get port from environment variable for Railway
if __name__ == "__main__":
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
