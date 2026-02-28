const express = require('express');
const session = require('express-session');
const passport = require('passport');
const DiscordStrategy = require('passport-discord').Strategy;
const LocalStrategy = require('passport-local').Strategy;
const fileUpload = require('express-fileupload');
const path = require('path');
const fs = require('fs');
const QRCode = require('qrcode');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const axios = require('axios');
const { setupDatabase } = require('./database');
const discordLogger = require('./discordLogger');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Python microservices URLs
const PYTHON_SERVICES = {
    analytics: process.env.ANALYTICS_SERVICE_URL || 'http://localhost:8001',
    ml: process.env.ML_SERVICE_URL || 'http://localhost:8002',
    reporting: process.env.REPORTING_SERVICE_URL || 'http://localhost:8003'
};

// Security Headers
app.use((req, res, next) => {
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('Content-Type', 'text/html; charset=UTF-8');
    res.charset = 'utf-8';
    next();
});

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

app.use(fileUpload({
    limits: { fileSize: 5 * 1024 * 1024 },
    createParentPath: true,
    abortOnLimit: true
}));

// Session setup
app.use(session({
    secret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex'),
    resave: false,
    saveUninitialized: false,
    cookie: {
        maxAge: 30 * 24 * 60 * 60 * 1000,
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax'
    },
    proxy: true
}));

app.use(passport.initialize());
app.use(passport.session());

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, '../frontend/views'));

// Database connection
let db;
setupDatabase().then(database => {
    db = database;
    console.log('✅ Database connected');
}).catch(err => {
    console.error('❌ Database connection error:', err);
});

// ==================== PASSPORT STRATEGIES ====================

// Local Strategy
passport.use('local', new LocalStrategy(
    async (username, password, done) => {
        try {
            console.log('📝 Local login attempt for:', username);
            
            if (!db) return done(null, false, { message: 'Database not ready' });

            const user = await db.get(
                'SELECT * FROM users WHERE username = ? OR email = ?', 
                [username, username]
            );
            
            if (!user) return done(null, false, { message: 'Invalid credentials' });
            if (user.is_banned) return done(null, false, { message: 'Account banned' });
            
            const isValid = await bcrypt.compare(password, user.password);
            if (!isValid) return done(null, false, { message: 'Invalid credentials' });
            
            await db.run('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?', [user.id]);
            await discordLogger.logLocalLogin(user, req?.ip);
            
            return done(null, user);
        } catch (error) {
            console.error('❌ Local strategy error:', error);
            return done(error);
        }
    }
));

// Discord Strategy
passport.use(new DiscordStrategy({
    clientID: process.env.DISCORD_CLIENT_ID,
    clientSecret: process.env.DISCORD_CLIENT_SECRET,
    callbackURL: process.env.DISCORD_CALLBACK_URL,
    scope: ['identify', 'email']
}, async (accessToken, refreshToken, profile, done) => {
    try {
        console.log('📝 Discord login attempt for:', profile.username);
        
        if (!db) return done(null, false, { message: 'Database not ready' });

        let user = await db.get('SELECT * FROM users WHERE discord_id = ?', [profile.id]);
        
        if (user?.is_banned) return done(null, false, { message: 'Account banned' });

        const adminIds = process.env.ADMIN_DISCORD_IDS?.split(',') || [];
        const isAdmin = adminIds.includes(profile.id);

        if (!user) {
            let username = profile.username;
            const existingUser = await db.get('SELECT * FROM users WHERE username = ?', [username]);
            if (existingUser) username = `${username}${Math.floor(Math.random() * 1000)}`;
            
            const result = await db.run(
                'INSERT INTO users (discord_id, username, email, avatar, is_admin) VALUES (?, ?, ?, ?, ?)',
                [profile.id, username, profile.email, profile.avatar, isAdmin]
            );
            
            user = await db.get('SELECT * FROM users WHERE id = ?', [result.lastID]);
            await discordLogger.logRegister(user);
        } else {
            await db.run(
                'UPDATE users SET last_login = CURRENT_TIMESTAMP, username = ?, email = ?, avatar = ?, is_admin = ? WHERE discord_id = ?',
                [profile.username, profile.email, profile.avatar, isAdmin, profile.id]
            );
            
            user = await db.get('SELECT * FROM users WHERE discord_id = ?', [profile.id]);
        }

        await discordLogger.logLogin(user, req?.ip, 'Discord');
        return done(null, user);
    } catch (error) {
        console.error('❌ Discord strategy error:', error);
        return done(error);
    }
}));

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
    try {
        const user = await db.get('SELECT * FROM users WHERE id = ?', [id]);
        done(null, user);
    } catch (error) {
        done(error);
    }
});

// ==================== MIDDLEWARE ====================

function ensureAuthenticated(req, res, next) {
    if (req.isAuthenticated()) return next();
    req.session.returnTo = req.originalUrl;
    res.redirect('/login');
}

function ensureAdmin(req, res, next) {
    if (req.isAuthenticated() && req.user?.is_admin) return next();
    res.status(403).render('error', { 
        message: 'Access denied. Admin only.',
        user: req.user || null 
    });
}

function ensureGuest(req, res, next) {
    if (req.isAuthenticated()) return res.redirect('/');
    next();
}

// ==================== PYTHON SERVICE PROXY ROUTES ====================

// Analytics endpoint - calls Python service
app.post('/api/analytics/sales', ensureAdmin, async (req, res) => {
    try {
        const { startDate, endDate, groupBy } = req.body;
        
        const response = await axios.post(`${PYTHON_SERVICES.analytics}/sales`, {
            startDate,
            endDate,
            groupBy
        }, {
            headers: { 'X-API-Key': process.env.PYTHON_API_KEY }
        });
        
        res.json(response.data);
    } catch (error) {
        console.error('Analytics service error:', error.message);
        res.status(500).json({ error: 'Analytics service unavailable' });
    }
});

// ML recommendations endpoint
app.get('/api/recommendations/:userId', ensureAuthenticated, async (req, res) => {
    try {
        const response = await axios.get(
            `${PYTHON_SERVICES.ml}/recommendations/${req.params.userId}`,
            {
                headers: { 'X-API-Key': process.env.PYTHON_API_KEY }
            }
        );
        
        res.json(response.data);
    } catch (error) {
        console.error('ML service error:', error.message);
        // Fallback to random products if ML service is down
        const products = await db.all('SELECT * FROM products ORDER BY RANDOM() LIMIT 5');
        res.json({ recommendations: products });
    }
});

// Report generation endpoint
app.post('/api/reports/generate', ensureAdmin, async (req, res) => {
    try {
        const { reportType, format, filters } = req.body;
        
        const response = await axios.post(`${PYTHON_SERVICES.reporting}/generate`, {
            reportType,
            format,
            filters
        }, {
            headers: { 'X-API-Key': process.env.PYTHON_API_KEY },
            responseType: format === 'pdf' ? 'arraybuffer' : 'json'
        });
        
        if (format === 'pdf') {
            res.setHeader('Content-Type', 'application/pdf');
            res.setHeader('Content-Disposition', `attachment; filename=report-${Date.now()}.pdf`);
            res.send(response.data);
        } else {
            res.json(response.data);
        }
    } catch (error) {
        console.error('Reporting service error:', error.message);
        res.status(500).json({ error: 'Report generation failed' });
    }
});

// ==================== AUTH ROUTES ====================

app.get('/login', ensureGuest, (req, res) => {
    res.render('login', { user: null, error: null, success: null });
});

app.get('/register', ensureGuest, (req, res) => {
    res.render('register', { user: null, error: null });
});

app.post('/register', ensureGuest, async (req, res) => {
    try {
        const { username, email, phone, password, confirmPassword } = req.body;
        
        if (!username || !email || !password || !confirmPassword) {
            return res.render('register', { user: null, error: 'All fields required' });
        }
        
        if (password !== confirmPassword) {
            return res.render('register', { user: null, error: 'Passwords do not match' });
        }
        
        if (password.length < 6) {
            return res.render('register', { user: null, error: 'Password must be at least 6 characters' });
        }
        
        const existingUser = await db.get(
            'SELECT * FROM users WHERE username = ? OR email = ?', 
            [username, email]
        );
        
        if (existingUser) {
            if (existingUser.username === username) {
                return res.render('register', { user: null, error: 'Username already exists' });
            }
            return res.render('register', { user: null, error: 'Email already registered' });
        }
        
        const hashedPassword = await bcrypt.hash(password, 10);
        
        const result = await db.run(
            'INSERT INTO users (username, email, phone, password, is_admin) VALUES (?, ?, ?, ?, ?)',
            [username, email, phone || null, hashedPassword, 0]
        );
        
        const newUser = await db.get('SELECT * FROM users WHERE id = ?', [result.lastID]);
        await discordLogger.logLocalRegister(newUser, req);
        
        res.render('login', { 
            user: null, 
            error: null, 
            success: 'Registration successful! Please login.' 
        });
        
    } catch (error) {
        console.error('Registration error:', error);
        res.render('register', { user: null, error: 'Registration failed' });
    }
});

app.post('/login', ensureGuest, (req, res, next) => {
    passport.authenticate('local', (err, user, info) => {
        if (err) return next(err);
        if (!user) {
            return res.render('login', { 
                user: null, 
                error: info.message || 'Invalid credentials',
                success: null 
            });
        }
        req.logIn(user, (err) => {
            if (err) return next(err);
            const returnTo = req.session.returnTo || '/';
            delete req.session.returnTo;
            return res.redirect(returnTo);
        });
    })(req, res, next);
});

app.get('/auth/discord', passport.authenticate('discord'));

app.get('/auth/discord/callback', 
    passport.authenticate('discord', { failureRedirect: '/login' }),
    (req, res) => {
        const returnTo = req.session.returnTo || '/';
        delete req.session.returnTo;
        res.redirect(returnTo);
    }
);

app.get('/logout', (req, res, next) => {
    req.logout(err => {
        if (err) return next(err);
        res.redirect('/');
    });
});

// ==================== PUBLIC ROUTES ====================

app.get('/', async (req, res) => {
    try {
        if (!db) {
            return res.render('index', { 
                user: req.user || null, 
                featuredProducts: [],
                brands: ['Adidas', 'Puma', 'Under Armour', 'New Balance']
            });
        }
        
        const featuredProducts = await db.all('SELECT * FROM products ORDER BY RANDOM() LIMIT 8');
        
        const brandRows = await db.all('SELECT DISTINCT brand FROM products WHERE brand IS NOT NULL');
        let brands = brandRows.map(row => row.brand);
        
        if (!brands.length) brands = ['Adidas', 'Puma', 'Under Armour', 'New Balance'];
        
        res.render('index', { 
            user: req.user || null, 
            featuredProducts: featuredProducts || [],
            brands
        });
    } catch (error) {
        console.error('Home page error:', error);
        res.render('index', { 
            user: req.user || null, 
            featuredProducts: [],
            brands: ['Adidas', 'Puma', 'Under Armour', 'New Balance']
        });
    }
});

app.get('/shop', async (req, res) => {
    try {
        const { category, brand, search } = req.query;
        const page = parseInt(req.query.page) || 1;
        const limit = 12;
        const offset = (page - 1) * limit;
        
        let query = 'SELECT * FROM products WHERE 1=1';
        let countQuery = 'SELECT COUNT(*) as count FROM products WHERE 1=1';
        const params = [];
        const countParams = [];

        if (category) {
            query += ' AND category = ?';
            countQuery += ' AND category = ?';
            params.push(category);
            countParams.push(category);
        }
        if (brand) {
            query += ' AND brand = ?';
            countQuery += ' AND brand = ?';
            params.push(brand);
            countParams.push(brand);
        }
        if (search) {
            query += ' AND (name LIKE ? OR description LIKE ?)';
            countQuery += ' AND (name LIKE ? OR description LIKE ?)';
            params.push(`%${search}%`, `%${search}%`);
            countParams.push(`%${search}%`, `%${search}%`);
        }

        query += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
        params.push(limit, offset);

        const products = await db.all(query, params);
        const totalCount = await db.get(countQuery, countParams);
        const totalPages = Math.ceil((totalCount?.count || 0) / limit);
        
        const categories = await db.all('SELECT DISTINCT category FROM products');
        const brands = await db.all('SELECT DISTINCT brand FROM products');

        res.render('shop', { 
            user: req.user || null, 
            products: products || [], 
            categories: categories || [], 
            brands: brands || [],
            filters: { category, brand, search },
            currentPage: page,
            totalPages: totalPages || 1
        });
    } catch (error) {
        console.error('Shop page error:', error);
        res.status(500).render('error', { message: 'Server error', user: req.user || null });
    }
});

app.get('/product/:id', async (req, res) => {
    try {
        const product = await db.get('SELECT * FROM products WHERE id = ?', [req.params.id]);
        if (!product) {
            return res.status(404).render('error', { message: 'Product not found', user: req.user || null });
        }

        if (req.user) await discordLogger.logProductView(req.user, product);

        const relatedProducts = await db.all(
            'SELECT * FROM products WHERE category = ? AND id != ? LIMIT 4',
            [product.category, product.id]
        );

        res.render('product', { 
            user: req.user || null, 
            product, 
            relatedProducts: relatedProducts || [] 
        });
    } catch (error) {
        console.error('Product page error:', error);
        res.status(500).render('error', { message: 'Server error', user: req.user || null });
    }
});

app.get('/terms', (req, res) => {
    res.render('terms', { user: req.user || null });
});

// ==================== CART ROUTES ====================

app.get('/cart', ensureAuthenticated, async (req, res) => {
    try {
        const cartItems = await db.all(`
            SELECT c.*, p.name, p.price, p.image_url, p.stock 
            FROM cart c 
            JOIN products p ON c.product_id = p.id 
            WHERE c.user_id = ?
        `, [req.user.id]);

        let subtotal = 0;
        cartItems.forEach(item => subtotal += item.price * item.quantity);

        const tax = subtotal * 0.18;
        const discount = req.session.discount || 0;
        const shipping = subtotal >= 999 ? 0 : 50;
        const total = subtotal + tax + shipping - discount;

        await discordLogger.logCartView(req.user);

        res.render('cart', { 
            user: req.user, 
            cartItems: cartItems || [], 
            subtotal: subtotal || 0,
            tax: tax || 0,
            shipping,
            discount: discount || 0,
            total: total || 0
        });
    } catch (error) {
        console.error('Cart page error:', error);
        res.status(500).render('error', { message: 'Server error', user: req.user || null });
    }
});

app.post('/cart/add/:productId', ensureAuthenticated, async (req, res) => {
    try {
        const productId = req.params.productId;
        const quantity = parseInt(req.body.quantity) || 1;

        const product = await db.get('SELECT * FROM products WHERE id = ?', [productId]);
        if (!product) return res.status(404).json({ error: 'Product not found' });
        if (product.stock < quantity) return res.status(400).json({ error: 'Insufficient stock' });

        const existingItem = await db.get(
            'SELECT * FROM cart WHERE user_id = ? AND product_id = ?',
            [req.user.id, productId]
        );

        if (existingItem) {
            const newQuantity = existingItem.quantity + quantity;
            if (newQuantity > product.stock) {
                return res.status(400).json({ error: 'Cannot add more than available stock' });
            }
            await db.run('UPDATE cart SET quantity = ? WHERE id = ?', [newQuantity, existingItem.id]);
        } else {
            await db.run('INSERT INTO cart (user_id, product_id, quantity) VALUES (?, ?, ?)',
                [req.user.id, productId, quantity]);
        }

        await discordLogger.logCartAdd(req.user, product, quantity);
        res.json({ success: true, message: 'Item added to cart' });
    } catch (error) {
        console.error('Add to cart error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

app.get('/cart/count', ensureAuthenticated, async (req, res) => {
    try {
        const result = await db.get('SELECT SUM(quantity) as count FROM cart WHERE user_id = ?', [req.user.id]);
        res.json({ count: result?.count || 0 });
    } catch (error) {
        console.error('Cart count error:', error);
        res.json({ count: 0 });
    }
});

app.post('/cart/remove/:cartId', ensureAuthenticated, async (req, res) => {
    try {
        await db.run('DELETE FROM cart WHERE id = ? AND user_id = ?', [req.params.cartId, req.user.id]);
        res.json({ success: true });
    } catch (error) {
        console.error('Remove from cart error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/cart/update/:cartId', ensureAuthenticated, async (req, res) => {
    try {
        const { quantity } = req.body;
        await db.run('UPDATE cart SET quantity = ? WHERE id = ? AND user_id = ?', 
            [quantity, req.params.cartId, req.user.id]);
        res.json({ success: true });
    } catch (error) {
        console.error('Update cart error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/cart/clear', ensureAuthenticated, async (req, res) => {
    try {
        await db.run('DELETE FROM cart WHERE user_id = ?', [req.user.id]);
        res.json({ success: true });
    } catch (error) {
        console.error('Clear cart error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// ==================== CHECKOUT ROUTES ====================

app.get('/checkout', ensureAuthenticated, async (req, res) => {
    try {
        const cartItems = await db.all(`
            SELECT c.*, p.name, p.price, p.image_url, p.stock 
            FROM cart c 
            JOIN products p ON c.product_id = p.id 
            WHERE c.user_id = ?
        `, [req.user.id]);

        if (cartItems.length === 0) return res.redirect('/cart');

        let subtotal = 0;
        cartItems.forEach(item => subtotal += item.price * item.quantity);

        const tax = subtotal * 0.18;
        const discount = req.session.discount || 0;
        const shipping = subtotal >= 999 ? 0 : 50;
        const total = subtotal + tax + shipping - discount;

        const tempOrderId = 'TEMP' + Date.now();
        const upiId = process.env.UPI_ID || 'sportswear@okhdfcbank';
        const payeeName = 'SportsWear';
        const amount = total.toFixed(2);
        
        const upiUrl = `upi://pay?pa=${upiId}&pn=${encodeURIComponent(payeeName)}&am=${amount}&cu=INR&tn=${encodeURIComponent('Order ' + tempOrderId)}`;
        const qrCodeDataUrl = await QRCode.toDataURL(upiUrl);

        res.render('checkout', { 
            user: req.user, 
            cartItems: cartItems || [], 
            subtotal: subtotal || 0,
            tax: tax || 0,
            shipping,
            discount: discount || 0,
            total: total || 0,
            qrCodeDataUrl: qrCodeDataUrl || null,
            upiId,
            tempOrderId,
            paymentMethods: ['UPI', 'Paytm', 'Google Pay', 'QR Code']
        });
    } catch (error) {
        console.error('Checkout page error:', error);
        res.status(500).render('error', { message: 'Server error', user: req.user || null });
    }
});

app.post('/checkout/process', ensureAuthenticated, async (req, res) => {
    try {
        const { paymentMethod, address, city, pincode, phone, notes } = req.body;
        const fullAddress = `${address}, ${city} - ${pincode}`;
        let paymentProof = null;

        if (paymentMethod === 'QR Code' && req.files?.paymentProof) {
            const file = req.files.paymentProof;
            const fileName = `proof_${Date.now()}_${file.name.replace(/[^a-zA-Z0-9.]/g, '')}`;
            const uploadPath = path.join(__dirname, '../frontend/public/uploads', fileName);
            await file.mv(uploadPath);
            paymentProof = `/uploads/${fileName}`;
        }

        const cartItems = await db.all(
            'SELECT c.*, p.price, p.id as product_id FROM cart c JOIN products p ON c.product_id = p.id WHERE c.user_id = ?',
            [req.user.id]
        );

        if (cartItems.length === 0) return res.status(400).json({ error: 'Cart is empty' });

        let subtotal = 0;
        cartItems.forEach(item => subtotal += item.price * item.quantity);
        
        const tax = subtotal * 0.18;
        const shipping = subtotal >= 999 ? 0 : 50;
        const discount = req.session.discount || 0;
        const total = subtotal + tax + shipping - discount;
        const orderNumber = 'ORD' + Date.now() + Math.floor(Math.random() * 1000);

        await db.run('BEGIN TRANSACTION');

        const orderResult = await db.run(`
            INSERT INTO orders (user_id, order_number, total_amount, payment_method, shipping_address, city, pincode, phone, notes, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `, [req.user.id, orderNumber, total, paymentMethod, fullAddress, city, pincode, phone, notes, 'pending']);

        for (const item of cartItems) {
            await db.run(`
                INSERT INTO order_items (order_id, product_id, quantity, price)
                VALUES (?, ?, ?, ?)
            `, [orderResult.lastID, item.product_id, item.quantity, item.price]);

            await db.run('UPDATE products SET stock = stock - ? WHERE id = ?', [item.quantity, item.product_id]);
        }

        await db.run(`
            INSERT INTO payments (order_id, user_id, amount, payment_method, payment_proof, status)
            VALUES (?, ?, ?, ?, ?, ?)
        `, [orderResult.lastID, req.user.id, total, paymentMethod, paymentProof, 'pending']);

        await db.run('DELETE FROM cart WHERE user_id = ?', [req.user.id]);
        await db.run('COMMIT');

        const shippingDetails = { fullAddress, city, pincode, phone };
        await discordLogger.logOrderCreate(req.user, { order_number: orderNumber, ...order }, cartItems, shippingDetails);
        await discordLogger.logPaymentInit(req.user, { order_id: orderResult.lastID, amount: total, payment_method: paymentMethod }, shippingDetails);

        // Call Python analytics service to track sale
        try {
            await axios.post(`${PYTHON_SERVICES.analytics}/track-sale`, {
                orderId: orderResult.lastID,
                userId: req.user.id,
                amount: total,
                items: cartItems.map(i => ({ productId: i.product_id, quantity: i.quantity, price: i.price }))
            }, { headers: { 'X-API-Key': process.env.PYTHON_API_KEY } });
        } catch (e) {
            console.error('Failed to track sale in analytics:', e.message);
        }

        res.redirect('/order-confirmation/' + orderResult.lastID);
    } catch (error) {
        await db.run('ROLLBACK');
        console.error('Checkout error:', error);
        await discordLogger.logError(error, { location: 'checkout', user: req.user });
        res.status(500).json({ error: 'Server error' });
    }
});

app.get('/order-confirmation/:id', ensureAuthenticated, async (req, res) => {
    try {
        const order = await db.get(`
            SELECT o.*, u.username 
            FROM orders o 
            JOIN users u ON o.user_id = u.id 
            WHERE o.id = ? AND o.user_id = ?
        `, [req.params.id, req.user.id]);

        if (!order) {
            return res.status(404).render('error', { message: 'Order not found', user: req.user || null });
        }

        const orderItems = await db.all(`
            SELECT oi.*, p.name, p.image_url 
            FROM order_items oi 
            JOIN products p ON oi.product_id = p.id 
            WHERE oi.order_id = ?
        `, [req.params.id]);

        res.render('order-confirmation', { user: req.user, order, orderItems: orderItems || [] });
    } catch (error) {
        console.error('Order confirmation error:', error);
        res.status(500).render('error', { message: 'Server error', user: req.user || null });
    }
});

// ==================== USER PROFILE ROUTES ====================

app.get('/profile', ensureAuthenticated, async (req, res) => {
    try {
        const orderStats = await db.get(`
            SELECT COUNT(*) as total_orders, SUM(total_amount) as total_spent
            FROM orders WHERE user_id = ?
        `, [req.user.id]);

        const recentOrders = await db.all(`
            SELECT * FROM orders WHERE user_id = ? ORDER BY created_at DESC LIMIT 5
        `, [req.user.id]);

        const wishlistItems = await db.all(`
            SELECT w.*, p.name, p.price, p.image_url 
            FROM wishlist w JOIN products p ON w.product_id = p.id 
            WHERE w.user_id = ? ORDER BY w.added_at DESC
        `, [req.user.id]);

        // Get ML recommendations
        let recommendations = [];
        try {
            const mlResponse = await axios.get(`${PYTHON_SERVICES.ml}/recommendations/${req.user.id}`, {
                headers: { 'X-API-Key': process.env.PYTHON_API_KEY }
            });
            recommendations = mlResponse.data.recommendations || [];
        } catch (e) {
            console.error('ML service error:', e.message);
        }

        res.render('profile', { 
            user: req.user, 
            stats: orderStats || { total_orders: 0, total_spent: 0 },
            orders: recentOrders || [],
            wishlist: wishlistItems || [],
            recommendations
        });
    } catch (error) {
        console.error('Profile error:', error);
        res.status(500).render('error', { message: 'Server error', user: req.user || null });
    }
});

app.post('/wishlist/add/:productId', ensureAuthenticated, async (req, res) => {
    try {
        await db.run('INSERT OR IGNORE INTO wishlist (user_id, product_id) VALUES (?, ?)',
            [req.user.id, req.params.productId]);
        res.json({ success: true });
    } catch (error) {
        console.error('Wishlist add error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/wishlist/remove/:productId', ensureAuthenticated, async (req, res) => {
    try {
        await db.run('DELETE FROM wishlist WHERE user_id = ? AND product_id = ?',
            [req.user.id, req.params.productId]);
        res.json({ success: true });
    } catch (error) {
        console.error('Wishlist remove error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// ==================== ORDER HISTORY ROUTES ====================

app.get('/history', ensureAuthenticated, async (req, res) => {
    try {
        const orders = await db.all(`
            SELECT o.*, COUNT(oi.id) as item_count 
            FROM orders o LEFT JOIN order_items oi ON o.id = oi.order_id 
            WHERE o.user_id = ? GROUP BY o.id ORDER BY o.created_at DESC
        `, [req.user.id]);

        for (let order of orders) {
            order.items = await db.all(`
                SELECT oi.*, p.name, p.image_url 
                FROM order_items oi JOIN products p ON oi.product_id = p.id 
                WHERE oi.order_id = ?
            `, [order.id]);
        }

        res.render('history', { user: req.user, orders: orders || [] });
    } catch (error) {
        console.error('History error:', error);
        res.status(500).render('error', { message: 'Server error', user: req.user || null });
    }
});

app.get('/order/:id', ensureAuthenticated, async (req, res) => {
    try {
        const order = await db.get(`
            SELECT o.*, u.username, u.discord_id 
            FROM orders o JOIN users u ON o.user_id = u.id 
            WHERE o.id = ? AND o.user_id = ?
        `, [req.params.id, req.user.id]);
        
        if (!order) {
            return res.status(404).render('error', { message: 'Order not found', user: req.user || null });
        }
        
        const orderItems = await db.all(`
            SELECT oi.*, p.name, p.image_url 
            FROM order_items oi JOIN products p ON oi.product_id = p.id 
            WHERE oi.order_id = ?
        `, [req.params.id]);
        
        const payment = await db.get('SELECT * FROM payments WHERE order_id = ?', [req.params.id]);
        
        res.render('order-details', { 
            user: req.user, 
            order, 
            orderItems: orderItems || [],
            payment: payment || null 
        });
    } catch (error) {
        console.error('Order details error:', error);
        res.status(500).render('error', { message: 'Server error', user: req.user || null });
    }
});

// ==================== ADMIN ROUTES ====================

app.get('/admin', ensureAdmin, async (req, res) => {
    try {
        await discordLogger.logAdminLogin(req.user);

        const totalUsers = await db.get('SELECT COUNT(*) as count FROM users');
        const totalOrders = await db.get('SELECT COUNT(*) as count FROM orders');
        const totalProducts = await db.get('SELECT COUNT(*) as count FROM products');
        const totalRevenue = await db.get('SELECT SUM(total_amount) as total FROM orders WHERE status = "completed"');
        const pendingOrders = await db.get('SELECT COUNT(*) as count FROM orders WHERE status = "pending"');
        
        const recentOrders = await db.all(`
            SELECT o.*, u.username FROM orders o JOIN users u ON o.user_id = u.id 
            ORDER BY o.created_at DESC LIMIT 10
        `);
        
        const recentUsers = await db.all('SELECT * FROM users ORDER BY created_at DESC LIMIT 10');

        // Get analytics from Python service
        let salesData = null;
        try {
            const analyticsRes = await axios.get(`${PYTHON_SERVICES.analytics}/dashboard`, {
                headers: { 'X-API-Key': process.env.PYTHON_API_KEY }
            });
            salesData = analyticsRes.data;
        } catch (e) {
            console.error('Analytics service error:', e.message);
        }

        const stats = {
            totalUsers: totalUsers || { count: 0 },
            totalOrders: totalOrders || { count: 0 },
            totalProducts: totalProducts || { count: 0 },
            totalRevenue: totalRevenue || { total: 0 },
            pendingOrders: pendingOrders || { count: 0 },
            recentOrders: recentOrders || [],
            recentUsers: recentUsers || [],
            salesData
        };

        res.render('admin/dashboard', { user: req.user, stats });
    } catch (error) {
        console.error('Admin dashboard error:', error);
        res.status(500).render('error', { message: 'Server error', user: req.user || null });
    }
});

app.get('/admin/users', ensureAdmin, async (req, res) => {
    try {
        const users = await db.all(`
            SELECT u.*, 
                   (SELECT COUNT(*) FROM orders WHERE user_id = u.id) as order_count,
                   (SELECT SUM(total_amount) FROM orders WHERE user_id = u.id AND status = 'completed') as total_spent
            FROM users u ORDER BY u.created_at DESC
        `);

        res.render('admin/users', { user: req.user, users: users || [] });
    } catch (error) {
        console.error('Admin users error:', error);
        res.status(500).render('error', { message: 'Server error', user: req.user || null });
    }
});

app.post('/admin/users/:userId/ban', ensureAdmin, async (req, res) => {
    try {
        const targetUser = await db.get('SELECT * FROM users WHERE id = ?', [req.params.userId]);
        await db.run('UPDATE users SET is_banned = ? WHERE id = ?', 
            [req.body.action === 'ban' ? 1 : 0, req.params.userId]);

        await discordLogger.logAdminAction(req.user, 
            `${req.body.action === 'ban' ? 'Banned' : 'Unbanned'} user`, 
            `User: ${targetUser.username}`);
        res.json({ success: true });
    } catch (error) {
        console.error('Ban user error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

app.get('/admin/products', ensureAdmin, async (req, res) => {
    try {
        const products = await db.all('SELECT * FROM products ORDER BY created_at DESC');
        const categories = await db.all('SELECT DISTINCT category FROM products');
        const brands = await db.all('SELECT DISTINCT brand FROM products');
        
        res.render('admin/products', { 
            user: req.user, 
            products: products || [],
            categories: categories || [],
            brands: brands || []
        });
    } catch (error) {
        console.error('Admin products error:', error);
        res.status(500).render('error', { message: 'Server error', user: req.user || null });
    }
});

app.post('/admin/products', ensureAdmin, async (req, res) => {
    try {
        const { name, description, price, category, brand, stock } = req.body;
        let imageUrl = '/images/default-product.jpg';

        if (req.files?.image) {
            const file = req.files.image;
            const fileName = `product_${Date.now()}_${file.name.replace(/[^a-zA-Z0-9.]/g, '')}`;
            const uploadPath = path.join(__dirname, '../frontend/public/uploads', fileName);
            await file.mv(uploadPath);
            imageUrl = `/uploads/${fileName}`;
        }

        const result = await db.run(`
            INSERT INTO products (name, description, price, category, brand, image_url, stock)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        `, [name, description, price, category, brand, imageUrl, stock]);

        await discordLogger.logProductAdd(req.user, { id: result.lastID, name, price, category, brand, stock });
        res.redirect('/admin/products');
    } catch (error) {
        console.error('Add product error:', error);
        res.status(500).render('error', { message: 'Server error', user: req.user || null });
    }
});

app.post('/admin/products/:id/edit', ensureAdmin, async (req, res) => {
    try {
        const { name, description, price, category, brand, stock } = req.body;
        const oldProduct = await db.get('SELECT * FROM products WHERE id = ?', [req.params.id]);

        let imageUrl = oldProduct.image_url;
        if (req.files?.image) {
            const file = req.files.image;
            const fileName = `product_${Date.now()}_${file.name.replace(/[^a-zA-Z0-9.]/g, '')}`;
            const uploadPath = path.join(__dirname, '../frontend/public/uploads', fileName);
            await file.mv(uploadPath);
            imageUrl = `/uploads/${fileName}`;
        }

        await db.run(`
            UPDATE products SET name = ?, description = ?, price = ?, category = ?, brand = ?, 
            image_url = ?, stock = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?
        `, [name, description, price, category, brand, imageUrl, stock, req.params.id]);

        await discordLogger.logProductEdit(req.user, { name, price }, 'Product updated');
        res.redirect('/admin/products');
    } catch (error) {
        console.error('Edit product error:', error);
        res.status(500).render('error', { message: 'Server error', user: req.user || null });
    }
});

app.post('/admin/products/:id/delete', ensureAdmin, async (req, res) => {
    try {
        const product = await db.get('SELECT * FROM products WHERE id = ?', [req.params.id]);
        await db.run('DELETE FROM products WHERE id = ?', [req.params.id]);
        await discordLogger.logProductDelete(req.user, product);
        res.json({ success: true });
    } catch (error) {
        console.error('Delete product error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

app.get('/admin/orders', ensureAdmin, async (req, res) => {
    try {
        const orders = await db.all(`
            SELECT o.*, u.username, u.discord_id,
                   (SELECT COUNT(*) FROM order_items WHERE order_id = o.id) as item_count,
                   p.payment_proof, p.status as payment_status
            FROM orders o JOIN users u ON o.user_id = u.id
            LEFT JOIN payments p ON o.id = p.order_id
            ORDER BY o.created_at DESC
        `);

        res.render('admin/orders', { user: req.user, orders: orders || [] });
    } catch (error) {
        console.error('Admin orders error:', error);
        res.status(500).render('error', { message: 'Server error', user: req.user || null });
    }
});

app.post('/admin/orders/:id/status', ensureAdmin, async (req, res) => {
    try {
        const { status } = req.body;
        const order = await db.get('SELECT * FROM orders WHERE id = ?', [req.params.id]);
        const oldStatus = order.status;

        await db.run('UPDATE orders SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?', 
            [status, req.params.id]);

        await discordLogger.logOrderUpdate(req.user, order, oldStatus, status);
        res.json({ success: true });
    } catch (error) {
        console.error('Update order status error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// ==================== BOT STATUS ROUTES ====================

app.get('/bot-status', (req, res) => {
    try {
        const status = discordLogger.getStatus();
        res.json({ success: true, ...status });
    } catch (error) {
        console.error('Error getting bot status:', error);
        res.status(500).json({ success: false, error: 'Could not retrieve bot status' });
    }
});

app.get('/health', (req, res) => {
    res.json({ 
        status: 'healthy',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        database: db ? 'connected' : 'disconnected',
        bot: discordLogger.getStatus().ready ? 'connected' : 'disconnected'
    });
});

app.get('/status', (req, res) => {
    const botStatus = discordLogger.getStatus();
    res.send(`
        <html>
        <head><title>SportsWear Status</title>
        <style>
            body { font-family: Arial; text-align: center; padding: 50px; background: #1a1a1a; color: white; }
            .online { background: #27ae60; padding: 20px; border-radius: 10px; }
            .offline { background: #e74c3c; padding: 20px; border-radius: 10px; }
            .info { background: #34495e; padding: 20px; border-radius: 10px; margin-top: 20px; }
        </style>
        </head>
        <body>
            <h1>SportsWear Status</h1>
            <div class="${botStatus.ready ? 'online' : 'offline'}">
                <h2>Bot is ${botStatus.ready ? '🟢 ONLINE' : '🔴 OFFLINE'}</h2>
            </div>
            <div class="info">
                <p>Bot: ${botStatus.user?.tag || 'N/A'}</p>
                <p>Servers: ${botStatus.guilds}</p>
                <p>Uptime: ${Math.floor(process.uptime() / 60)} minutes</p>
            </div>
        </body>
        </html>
    `);
});

// ==================== API ROUTES ====================

app.get('/api/search', async (req, res) => {
    try {
        const { q } = req.query;
        const products = await db.all(`
            SELECT * FROM products WHERE name LIKE ? OR description LIKE ? LIMIT 20
        `, [`%${q}%`, `%${q}%`]);
        res.json(products || []);
    } catch (error) {
        console.error('Search error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// ==================== ERROR HANDLING ====================

app.use((req, res) => {
    res.status(404).render('error', { message: 'Page not found', user: req.user || null });
});

app.use((err, req, res, next) => {
    console.error('❌ Server error:', err);
    discordLogger.logError(err, { location: req.path, user: req.user });
    res.status(500).render('error', { message: 'Something went wrong!', user: req.user || null });
});

// ==================== START SERVER ====================

app.listen(PORT, '0.0.0.0', () => {
    console.log(`✅ Server running on port ${PORT}`);
    discordLogger.logSystem(`Server started on port ${PORT}`, 'info');
});

module.exports = app;
