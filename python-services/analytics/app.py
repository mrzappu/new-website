from fastapi import FastAPI, HTTPException, Depends, Security
from fastapi.security import APIKeyHeader
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import asyncpg
import os
from dotenv import load_dotenv

load_dotenv()

app = FastAPI(title="Analytics Service", version="1.0.0")

# Security
API_KEY = os.getenv("PYTHON_API_KEY", "default-dev-key")
api_key_header = APIKeyHeader(name="X-API-Key")

async def verify_api_key(api_key: str = Security(api_key_header)):
    if api_key != API_KEY:
        raise HTTPException(status_code=403, detail="Invalid API key")
    return api_key

# Database connection pool
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://user:password@postgres:5432/myapp")

class SaleRequest(BaseModel):
    orderId: int
    userId: int
    amount: float
    items: List[Dict[str, Any]]

class SalesQuery(BaseModel):
    startDate: Optional[str] = None
    endDate: Optional[str] = None
    groupBy: str = "day"  # day, week, month, year

@app.on_event("startup")
async def startup():
    app.state.db_pool = await asyncpg.create_pool(DATABASE_URL)

@app.on_event("shutdown")
async def shutdown():
    await app.state.db_pool.close()

@app.post("/track-sale", dependencies=[Depends(verify_api_key)])
async def track_sale(sale: SaleRequest):
    """Track a sale for analytics"""
    try:
        async with app.state.db_pool.acquire() as conn:
            # Insert into analytics table
            await conn.execute("""
                INSERT INTO analytics_sales (order_id, user_id, amount, items, created_at)
                VALUES ($1, $2, $3, $4, $5)
            """, sale.orderId, sale.userId, sale.amount, str(sale.items), datetime.now())
        
        return {"status": "success", "message": "Sale tracked"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/sales", dependencies=[Depends(verify_api_key)])
async def get_sales(query: SalesQuery):
    """Get sales analytics"""
    try:
        end_date = datetime.now() if not query.endDate else datetime.fromisoformat(query.endDate)
        start_date = end_date - timedelta(days=30) if not query.startDate else datetime.fromisoformat(query.startDate)
        
        async with app.state.db_pool.acquire() as conn:
            # Get sales data
            rows = await conn.fetch("""
                SELECT amount, created_at FROM orders 
                WHERE status = 'completed' 
                AND created_at BETWEEN $1 AND $2
            """, start_date, end_date)
        
        if not rows:
            return {"sales": [], "summary": {"total": 0, "average": 0, "count": 0}}
        
        # Convert to DataFrame for analysis
        df = pd.DataFrame([dict(row) for row in rows])
        df['date'] = pd.to_datetime(df['created_at'])
        
        # Group by specified period
        if query.groupBy == "day":
            df['period'] = df['date'].dt.date
        elif query.groupBy == "week":
            df['period'] = df['date'].dt.isocalendar().week
        elif query.groupBy == "month":
            df['period'] = df['date'].dt.month
        else:
            df['period'] = df['date'].dt.year
        
        grouped = df.groupby('period')['amount'].agg(['sum', 'mean', 'count']).reset_index()
        
        # Calculate statistics
        stats = {
            "total": float(df['amount'].sum()),
            "average": float(df['amount'].mean()),
            "median": float(df['amount'].median()),
            "std": float(df['amount'].std()),
            "min": float(df['amount'].min()),
            "max": float(df['amount'].max()),
            "count": len(df)
        }
        
        return {
            "sales": grouped.to_dict(orient='records'),
            "summary": stats
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/dashboard", dependencies=[Depends(verify_api_key)])
async def get_dashboard():
    """Get dashboard analytics"""
    try:
        async with app.state.db_pool.acquire() as conn:
            # Today's sales
            today = datetime.now().date()
            today_rows = await conn.fetch("""
                SELECT COALESCE(SUM(amount), 0) as total, COUNT(*) as count
                FROM orders WHERE status = 'completed' AND DATE(created_at) = $1
            """, today)
            
            # This week's sales
            week_start = today - timedelta(days=today.weekday())
            week_rows = await conn.fetch("""
                SELECT COALESCE(SUM(amount), 0) as total, COUNT(*) as count
                FROM orders WHERE status = 'completed' AND DATE(created_at) >= $1
            """, week_start)
            
            # This month's sales
            month_start = today.replace(day=1)
            month_rows = await conn.fetch("""
                SELECT COALESCE(SUM(amount), 0) as total, COUNT(*) as count
                FROM orders WHERE status = 'completed' AND DATE(created_at) >= $1
            """, month_start)
            
            # Top products
            top_products = await conn.fetch("""
                SELECT p.name, SUM(oi.quantity) as total_sold, SUM(oi.quantity * oi.price) as revenue
                FROM order_items oi
                JOIN products p ON oi.product_id = p.id
                JOIN orders o ON oi.order_id = o.id
                WHERE o.status = 'completed'
                GROUP BY p.id, p.name
                ORDER BY revenue DESC
                LIMIT 10
            """)
            
            return {
                "today": dict(today_rows[0]),
                "this_week": dict(week_rows[0]),
                "this_month": dict(month_rows[0]),
                "top_products": [dict(p) for p in top_products]
            }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/health")
async def health():
    return {"status": "healthy", "service": "analytics"}
