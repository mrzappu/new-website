from fastapi import FastAPI, HTTPException, Depends, Security
from fastapi.security import APIKeyHeader
from fastapi.responses import Response
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import io
import base64
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
import asyncpg
import os
from datetime import datetime, timedelta
import json

app = FastAPI(title="Reporting Service", version="1.0.0")

# Security
API_KEY = os.getenv("PYTHON_API_KEY", "default-dev-key")
api_key_header = APIKeyHeader(name="X-API-Key")

async def verify_api_key(api_key: str = Security(api_key_header)):
    if api_key != API_KEY:
        raise HTTPException(status_code=403, detail="Invalid API key")
    return api_key

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://user:password@postgres:5432/myapp")

class ReportRequest(BaseModel):
    reportType: str  # sales, users, products, inventory
    format: str  # json, csv, pdf, png
    filters: Optional[Dict[str, Any]] = {}
    dateRange: Optional[Dict[str, str]] = None

@app.on_event("startup")
async def startup():
    app.state.db_pool = await asyncpg.create_pool(DATABASE_URL)

@app.on_event("shutdown")
async def shutdown():
    await app.state.db_pool.close()

@app.post("/generate", dependencies=[Depends(verify_api_key)])
async def generate_report(request: ReportRequest):
    """Generate report in various formats"""
    try:
        async with app.state.db_pool.acquire() as conn:
            # Get data based on report type
            if request.reportType == "sales":
                data = await get_sales_data(conn, request.filters, request.dateRange)
            elif request.reportType == "users":
                data = await get_users_data(conn, request.filters, request.dateRange)
            elif request.reportType == "products":
                data = await get_products_data(conn, request.filters)
            elif request.reportType == "inventory":
                data = await get_inventory_data(conn)
            else:
                raise HTTPException(status_code=400, detail="Invalid report type")
            
            # Format output
            if request.format == "json":
                return data
            elif request.format == "csv":
                return await generate_csv(data)
            elif request.format == "pdf":
                return await generate_pdf(request.reportType, data)
            elif request.format == "png":
                return await generate_chart(request.reportType, data)
            else:
                raise HTTPException(status_code=400, detail="Invalid format")
                
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

async def get_sales_data(conn, filters, date_range):
    """Get sales data for reporting"""
    query = """
        SELECT o.order_number, o.total_amount, o.status, o.created_at,
               u.username, u.email,
               COUNT(oi.id) as item_count
        FROM orders o
        JOIN users u ON o.user_id = u.id
        LEFT JOIN order_items oi ON o.id = oi.order_id
        WHERE 1=1
    """
    params = []
    
    if date_range:
        query += " AND o.created_at BETWEEN $1 AND $2"
        params.extend([date_range['start'], date_range['end']])
    
    if filters.get('status'):
        query += f" AND o.status = ${len(params) + 1}"
        params.append(filters['status'])
    
    query += " GROUP BY o.id, u.id ORDER BY o.created_at DESC"
    
    rows = await conn.fetch(query, *params)
    return [dict(row) for row in rows]

async def get_users_data(conn, filters, date_range):
    """Get user data for reporting"""
    query = """
        SELECT u.id, u.username, u.email, u.is_admin, u.created_at,
               COUNT(DISTINCT o.id) as order_count,
               COALESCE(SUM(o.total_amount), 0) as total_spent
        FROM users u
        LEFT JOIN orders o ON u.id = o.user_id AND o.status = 'completed'
        WHERE 1=1
    """
    params = []
    
    if date_range:
        query += " AND u.created_at BETWEEN $1 AND $2"
        params.extend([date_range['start'], date_range['end']])
    
    query += " GROUP BY u.id ORDER BY u.created_at DESC"
    
    rows = await conn.fetch(query, *params)
    return [dict(row) for row in rows]

async def get_products_data(conn, filters):
    """Get product data for reporting"""
    query = """
        SELECT p.id, p.name, p.price, p.category, p.brand, p.stock,
               COALESCE(SUM(oi.quantity), 0) as total_sold,
               COALESCE(SUM(oi.quantity * oi.price), 0) as total_revenue
        FROM products p
        LEFT JOIN order_items oi ON p.id = oi.product_id
        LEFT JOIN orders o ON oi.order_id = o.id AND o.status = 'completed'
        WHERE 1=1
    """
    params = []
    
    if filters.get('category'):
        query += f" AND p.category = ${len(params) + 1}"
        params.append(filters['category'])
    
    if filters.get('brand'):
        query += f" AND p.brand = ${len(params) + 1}"
        params.append(filters['brand'])
    
    query += " GROUP BY p.id ORDER BY total_revenue DESC"
    
    rows = await conn.fetch(query, *params)
    return [dict(row) for row in rows]

async def get_inventory_data(conn):
    """Get inventory data for reporting"""
    rows = await conn.fetch("""
        SELECT category, brand,
               COUNT(*) as product_count,
               SUM(stock) as total_stock,
               AVG(price) as avg_price,
               SUM(CASE WHEN stock = 0 THEN 1 ELSE 0 END) as out_of_stock
        FROM products
        GROUP BY category, brand
        ORDER BY category, brand
    """)
    return [dict(row) for row in rows]

async def generate_csv(data):
    """Convert data to CSV"""
    if not data:
        return Response(content="No data", media_type="text/csv")
    
    df = pd.DataFrame(data)
    csv_data = df.to_csv(index=False)
    return Response(
        content=csv_data,
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=report-{datetime.now().strftime('%Y%m%d')}.csv"}
    )

async def generate_pdf(report_type, data):
    """Generate PDF report"""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4)
    styles = getSampleStyleSheet()
    story = []
    
    # Title
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        spaceAfter=30,
        alignment=1  # Center
    )
    story.append(Paragraph(f"{report_type.title()} Report", title_style))
    story.append(Spacer(1, 12))
    
    # Date
    story.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}", styles['Normal']))
    story.append(Spacer(1, 20))
    
    if data:
        # Convert to DataFrame for table
        df = pd.DataFrame(data)
        
        # Limit columns for readability
        if len(df.columns) > 6:
            df = df.iloc[:, :6]
        
        # Create table data
        table_data = [df.columns.tolist()] + df.values.tolist()
        
        # Create table
        table = Table(table_data)
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        story.append(table)
    
    # Build PDF
    doc.build(story)
    pdf_data = buffer.getvalue()
    buffer.close()
    
    return Response(
        content=pdf_data,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=report-{datetime.now().strftime('%Y%m%d')}.pdf"}
    )

async def generate_chart(report_type, data):
    """Generate chart as PNG"""
    if not data:
        return Response(content="No data", media_type="text/plain")
    
    df = pd.DataFrame(data)
    
    plt.figure(figsize=(12, 6))
    
    if report_type == "sales":
        if 'created_at' in df.columns:
            df['date'] = pd.to_datetime(df['created_at']).dt.date
            daily = df.groupby('date')['total_amount'].sum()
            daily.plot(kind='line', marker='o')
            plt.title('Daily Sales')
            plt.xlabel('Date')
            plt.ylabel('Revenue (₹)')
            plt.xticks(rotation=45)
    
    elif report_type == "products":
        if 'total_sold' in df.columns:
            top = df.nlargest(10, 'total_sold')
            sns.barplot(data=top, x='name', y='total_sold')
            plt.title('Top Selling Products')
            plt.xlabel('Product')
            plt.ylabel('Units Sold')
            plt.xticks(rotation=45)
    
    elif report_type == "inventory":
        if 'category' in df.columns:
            sns.barplot(data=df, x='category', y='total_stock')
            plt.title('Inventory by Category')
            plt.xlabel('Category')
            plt.ylabel('Total Stock')
    
    plt.tight_layout()
    
    # Save to bytes
    img_buffer = io.BytesIO()
    plt.savefig(img_buffer, format='png', dpi=100)
    plt.close()
    img_buffer.seek(0)
    
    return Response(
        content=img_buffer.getvalue(),
        media_type="image/png",
        headers={"Content-Disposition": f"attachment; filename=chart-{datetime.now().strftime('%Y%m%d')}.png"}
    )

@app.get("/health")
async def health():
    return {"status": "healthy", "service": "reporting"}
