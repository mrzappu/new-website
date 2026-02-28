from fastapi import FastAPI, HTTPException, Depends, Security
from fastapi.security import APIKeyHeader
from pydantic import BaseModel
from typing import List, Dict, Any
import pandas as pd
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
import asyncpg
import os
from datetime import datetime, timedelta
import json

app = FastAPI(title="ML Service", version="1.0.0")

# Security
API_KEY = os.getenv("PYTHON_API_KEY", "default-dev-key")
api_key_header = APIKeyHeader(name="X-API-Key")

async def verify_api_key(api_key: str = Security(api_key_header)):
    if api_key != API_KEY:
        raise HTTPException(status_code=403, detail="Invalid API key")
    return api_key

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://user:password@postgres:5432/myapp")

@app.on_event("startup")
async def startup():
    app.state.db_pool = await asyncpg.create_pool(DATABASE_URL)

@app.on_event("shutdown")
async def shutdown():
    await app.state.db_pool.close()

@app.get("/recommendations/{user_id}", dependencies=[Depends(verify_api_key)])
async def get_recommendations(user_id: int, limit: int = 5):
    """Get product recommendations for a user"""
    try:
        async with app.state.db_pool.acquire() as conn:
            # Get user's order history
            user_orders = await conn.fetch("""
                SELECT oi.product_id, oi.quantity 
                FROM order_items oi
                JOIN orders o ON oi.order_id = o.id
                WHERE o.user_id = $1 AND o.status = 'completed'
            """, user_id)
            
            # Get all products
            all_products = await conn.fetch("SELECT * FROM products WHERE stock > 0")
            
            if not all_products:
                return {"recommendations": []}
            
            # Get user's wishlist
            wishlist = await conn.fetch("SELECT product_id FROM wishlist WHERE user_id = $1", user_id)
            wishlist_ids = [w['product_id'] for w in wishlist]
            
            # Get popular products (fallback)
            popular = await conn.fetch("""
                SELECT p.id, COUNT(oi.product_id) as order_count
                FROM products p
                LEFT JOIN order_items oi ON p.id = oi.product_id
                GROUP BY p.id
                ORDER BY order_count DESC
                LIMIT $1
            """, limit * 2)
            
            popular_ids = [p['id'] for p in popular]
            
            if user_orders:
                # Collaborative filtering: users who bought similar items
                user_product_ids = [uo['product_id'] for uo in user_orders]
                
                # Find other users who bought these products
                similar_users = await conn.fetch("""
                    SELECT DISTINCT o.user_id
                    FROM order_items oi
                    JOIN orders o ON oi.order_id = o.id
                    WHERE oi.product_id = ANY($1::int[]) AND o.user_id != $2
                    LIMIT 20
                """, user_product_ids, user_id)
                
                similar_user_ids = [su['user_id'] for su in similar_users]
                
                if similar_user_ids:
                    # Get products bought by similar users
                    recommendations = await conn.fetch("""
                        SELECT p.*, COUNT(oi.product_id) as relevance
                        FROM products p
                        JOIN order_items oi ON p.id = oi.product_id
                        JOIN orders o ON oi.order_id = o.id
                        WHERE o.user_id = ANY($1::int[])
                        AND p.id != ALL($2::int[])
                        AND p.stock > 0
                        GROUP BY p.id
                        ORDER BY relevance DESC
                        LIMIT $3
                    """, similar_user_ids, user_product_ids, limit)
                    
                    if recommendations:
                        return {"recommendations": [dict(r) for r in recommendations]}
            
            # Content-based filtering: similar to wishlist items
            if wishlist_ids:
                # Get product features for TF-IDF
                wishlist_products = await conn.fetch(
                    "SELECT name, description, category FROM products WHERE id = ANY($1::int[])",
                    wishlist_ids
                )
                
                if wishlist_products:
                    # Create feature text
                    wishlist_texts = [f"{p['name']} {p['description']} {p['category']}" for p in wishlist_products]
                    
                    # Get candidate products
                    candidates = await conn.fetch(
                        "SELECT id, name, description, category FROM products WHERE stock > 0 AND id != ALL($1::int[]) LIMIT 50",
                        wishlist_ids
                    )
                    
                    if candidates:
                        candidate_texts = [f"{c['name']} {c['description']} {c['category']}" for c in candidates]
                        
                        # TF-IDF vectorization
                        vectorizer = TfidfVectorizer(stop_words='english')
                        tfidf_matrix = vectorizer.fit_transform(wishlist_texts + candidate_texts)
                        
                        # Calculate similarity
                        similarity_scores = cosine_similarity(
                            tfidf_matrix[:len(wishlist_texts)], 
                            tfidf_matrix[len(wishlist_texts):]
                        )
                        
                        # Get top matches
                        avg_scores = similarity_scores.mean(axis=0)
                        top_indices = np.argsort(avg_scores)[-limit:][::-1]
                        
                        recommended_products = [dict(candidates[i]) for i in top_indices if i < len(candidates)]
                        if recommended_products:
                            return {"recommendations": recommended_products}
            
            # Fallback: popular products
            popular_products = await conn.fetch(
                "SELECT * FROM products WHERE id = ANY($1::int[]) LIMIT $2",
                popular_ids, limit
            )
            
            return {"recommendations": [dict(p) for p in popular_products]}
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/train", dependencies=[Depends(verify_api_key)])
async def train_model():
    """Train/retrain recommendation model"""
    try:
        async with app.state.db_pool.acquire() as conn:
            # Get all order data
            orders = await conn.fetch("""
                SELECT o.user_id, oi.product_id, oi.quantity
                FROM orders o
                JOIN order_items oi ON o.id = oi.order_id
                WHERE o.status = 'completed'
            """)
            
            # Create user-item matrix
            df = pd.DataFrame([dict(o) for o in orders])
            
            if len(df) > 0:
                # Create pivot table
                pivot = df.pivot_table(
                    index='user_id', 
                    columns='product_id', 
                    values='quantity',
                    fill_value=0
                )
                
                # Calculate item similarity matrix
                item_similarity = cosine_similarity(pivot.T)
                
                # Save model (in production, save to file/redis)
                app.state.item_similarity = item_similarity.tolist()
                app.state.item_ids = pivot.columns.tolist()
                
                return {"status": "success", "message": f"Model trained on {len(df)} interactions"}
            
            return {"status": "success", "message": "No data to train"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/health")
async def health():
    return {"status": "healthy", "service": "ml"}
