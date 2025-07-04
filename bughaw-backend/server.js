/*
================================================================================
-- BUGHWAW MULTI-LINE CORP - BACKEND API (FINAL PRODUCTION) --
This is the final, production-ready backend server. It provides all APIs for
the web admin panel and the agent mobile app.

Features & Fixes:
- Endpoints for sales summary, orders, and inventory are now fully functional.
- Implemented full CRUD (Create, Read, Update, Delete) logic for all modules.
- Advanced User Management:
  - Add users with specific roles (Admin, Agent).
  - Edit user roles and permissions (e.g., 'pos', 'dashboard').
  - Securely change user passwords.
- Secure authentication with JWT.
- Role-based and permission-based access control.
- Transactional order processing to ensure data integrity.
- Image upload handling for products.
- Automatic setup for default users on first run.
- Added robust error handling for JSON parsing in the login route.
- FIXED: Improved permissions parsing to handle edge cases and invalid JSON
================================================================================
*/

const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

// --- CONFIGURATION ---
const app = express();
const port = 5000;
const saltRounds = 10;
const JWT_SECRET = 'a-very-secure-and-complex-secret-key-for-bughaw-should-be-in-an-env-file';

// --- DATABASE CONNECTION ---
const db = mysql.createPool({
    host: 'localhost',
    user: 'root',
    password: 'canaman15', // IMPORTANT: Replace with your MySQL password
    database: 'bughaw_db',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
    dateStrings: true
}).promise();

// --- MIDDLEWARE & SETUP ---
app.use(cors());
app.use(express.json());

const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir);
}
app.use('/uploads', express.static(uploadsDir));

const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, 'uploads/'),
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
    }
});
const upload = multer({ storage: storage });

// --- HELPER FUNCTION FOR PERMISSIONS PARSING ---
const parsePermissions = (permissionsData) => {
    if (!permissionsData) {
        return [];
    }
    
    // If it's already an array, return it
    if (Array.isArray(permissionsData)) {
        return permissionsData;
    }
    
    // Handle string values
    if (typeof permissionsData === 'string') {
        // Handle special cases like "all"
        if (permissionsData.toLowerCase() === 'all') {
            return ['pos', 'dashboard', 'products', 'inventory', 'orders'];
        }
        
        // Try to parse as JSON
        try {
            const parsed = JSON.parse(permissionsData);
            return Array.isArray(parsed) ? parsed : [];
        } catch (e) {
            console.error(`Invalid permissions data: "${permissionsData}". Setting to empty array.`);
            return [];
        }
    }
    
    // Default fallback
    return [];
};

// --- AUTH MIDDLEWARE ---
const verifyToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) return res.status(401).json({ message: "Unauthorized: No token provided." });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ message: "Forbidden: Invalid or expired token." });
        req.user = user;
        next();
    });
};

const hasPermission = (requiredPermissions) => (req, res, next) => {
    const user = req.user;
    if (user.role === 'Super Admin') {
        return next();
    }
    if (user.permissions && requiredPermissions.some(p => user.permissions.includes(p))) {
        return next();
    }
    return res.status(403).json({ message: "Forbidden: You do not have permission to perform this action." });
};

const isSuperAdmin = (req, res, next) => {
    if (req.user.role !== 'Super Admin') {
        return res.status(403).json({ message: "Forbidden: Super Admin access required." });
    }
    next();
};

// ================================================================================
// --- API ROUTES ---
// ================================================================================

// POST /api/login
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ message: 'Username and password are required.' });
    
    try {
        const [users] = await db.query('SELECT * FROM users WHERE username = ?', [username]);
        if (users.length === 0) return res.status(401).json({ message: 'Invalid credentials.' });

        const user = users[0];
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(401).json({ message: 'Invalid credentials.' });

        // FIXED: Use the helper function to safely parse permissions
        const permissions = parsePermissions(user.permissions);

        const tokenPayload = { id: user.id, username: user.username, role: user.role, permissions };
        const token = jwt.sign(tokenPayload, JWT_SECRET, { expiresIn: '1d' });

        res.json({ token, user: tokenPayload });
    } catch (error) {
        console.error("Login Server Error:", error);
        if (error.code === 'ECONNREFUSED' || error.code === 'ER_ACCESS_DENIED_ERROR') {
             return res.status(500).json({ message: 'Database connection failed. Please check server credentials.' });
        }
        res.status(500).json({ message: 'Server error during login.' });
    }
});

// --- USER MANAGEMENT ---
app.get('/api/users', verifyToken, isSuperAdmin, async (req, res) => {
    try {
        const [users] = await db.query("SELECT id, username, role, permissions FROM users WHERE role != 'Super Admin'");
        res.json(users.map(u => ({
            ...u, 
            permissions: parsePermissions(u.permissions)
        })));
    } catch (error) { 
        console.error("Fetch Users Error:", error);
        res.status(500).json({ message: 'Failed to fetch users.' }); 
    }
});

app.post('/api/users/register', verifyToken, isSuperAdmin, async (req, res) => {
    const { username, password, role } = req.body;
    if (!username || !password || !role) return res.status(400).json({ message: 'Username, password, and role are required.' });
    
    let defaultPermissions = [];
    if (role === 'Agent') {
        defaultPermissions = ['pos'];
    } else if (role === 'Admin') {
        defaultPermissions = ['pos', 'dashboard', 'products', 'inventory', 'orders'];
    }
    
    try {
        const hashedPassword = await bcrypt.hash(password, saltRounds);
        await db.query(
            'INSERT INTO users (username, password, role, permissions) VALUES (?, ?, ?, ?)',
            [username, hashedPassword, role, JSON.stringify(defaultPermissions)]
        );
        res.status(201).json({ message: 'User created successfully.' });
    } catch (error) { 
        console.error("Create User Error:", error);
        if (error.code === 'ER_DUP_ENTRY') {
            res.status(400).json({ message: 'Username already exists.' });
        } else {
            res.status(500).json({ message: 'Failed to create user.' });
        }
    }
});

app.put('/api/users/:id', verifyToken, isSuperAdmin, async (req, res) => {
    const { id } = req.params;
    const { role, permissions } = req.body;
    if (!role || !permissions) {
        return res.status(400).json({ message: "Role and permissions are required." });
    }
    try {
        await db.query(
            'UPDATE users SET role = ?, permissions = ? WHERE id = ?',
            [role, JSON.stringify(permissions || []), id]
        );
        res.json({ message: 'User updated successfully.' });
    } catch (error) { 
        console.error("Update User Error:", error);
        res.status(500).json({ message: 'Failed to update user.' }); 
    }
});

app.delete('/api/users/:id', verifyToken, isSuperAdmin, async (req, res) => {
    const { id } = req.params;
    try {
        await db.query('DELETE FROM users WHERE id = ?', [id]);
        res.json({ message: 'User deleted successfully.' });
    } catch (error) {
        console.error("Delete User Error:", error);
        res.status(500).json({ message: 'Failed to delete user.' });
    }
});

app.put('/api/users/change-password', verifyToken, async (req, res) => {
    const { currentPassword, newPassword } = req.body;
    const userId = req.user.id;
    if (!currentPassword || !newPassword) return res.status(400).json({ message: "All password fields are required."});

    try {
        const [users] = await db.query('SELECT password FROM users WHERE id = ?', [userId]);
        if (users.length === 0) return res.status(404).json({ message: 'User not found.' });

        const isMatch = await bcrypt.compare(currentPassword, users[0].password);
        if (!isMatch) return res.status(400).json({ message: 'Incorrect current password.' });

        const hashedNewPassword = await bcrypt.hash(newPassword, saltRounds);
        await db.query('UPDATE users SET password = ? WHERE id = ?', [hashedNewPassword, userId]);
        res.json({ message: 'Password changed successfully.' });
    } catch (error) { 
        console.error("Change Password Error:", error);
        res.status(500).json({ message: 'Server error changing password.' }); 
    }
});

// --- PRODUCT ROUTES ---
app.get('/api/products', verifyToken, async (req, res) => {
    try {
        const query = `
            SELECT p.id, p.name, p.description, p.price, p.image_url, COALESCE(i.stock_quantity, 0) as stock
            FROM products p
            LEFT JOIN inventory i ON p.id = i.product_id
            ORDER BY p.name;
        `;
        const [products] = await db.query(query);
        res.json(products.map(p => ({...p, price: parseFloat(p.price) })));
    } catch (error) {
        console.error("Fetch Products Error:", error);
        res.status(500).json({ message: "Failed to fetch products" });
    }
});

app.post('/api/products', verifyToken, hasPermission(['products']), upload.single('image'), async (req, res) => {
    const { name, description, price } = req.body;
    if (!name || !price) return res.status(400).json({ message: 'Name and price are required.' });
    
    const imageUrl = req.file ? `/uploads/${req.file.filename}` : null;
    
    const connection = await db.getConnection();
    try {
        await connection.beginTransaction();
        
        const [productResult] = await connection.query(
            'INSERT INTO products (name, description, price, image_url) VALUES (?, ?, ?, ?)',
            [name, description || '', parseFloat(price), imageUrl]
        );
        
        const productId = productResult.insertId;
        
        await connection.query(
            'INSERT INTO inventory (product_id, stock_quantity) VALUES (?, ?)',
            [productId, 0]
        );
        
        await connection.commit();
        res.status(201).json({ message: 'Product created successfully.', productId });
    } catch (error) {
        await connection.rollback();
        console.error("Create Product Error:", error);
        res.status(500).json({ message: 'Failed to create product.' });
    } finally {
        connection.release();
    }
});

app.put('/api/products/:id', verifyToken, hasPermission(['products']), upload.single('image'), async (req, res) => {
    const { id } = req.params;
    const { name, description, price } = req.body;
    
    try {
        let updateQuery = 'UPDATE products SET name = ?, description = ?, price = ?';
        let params = [name, description || '', parseFloat(price)];
        
        if (req.file) {
            updateQuery += ', image_url = ?';
            params.push(`/uploads/${req.file.filename}`);
        }
        
        updateQuery += ' WHERE id = ?';
        params.push(id);
        
        await db.query(updateQuery, params);
        res.json({ message: 'Product updated successfully.' });
    } catch (error) {
        console.error("Update Product Error:", error);
        res.status(500).json({ message: 'Failed to update product.' });
    }
});

app.delete('/api/products/:id', verifyToken, hasPermission(['products']), async (req, res) => {
    const { id } = req.params;
    const connection = await db.getConnection();
    
    try {
        await connection.beginTransaction();
        
        await connection.query('DELETE FROM inventory WHERE product_id = ?', [id]);
        
        await connection.query('DELETE FROM products WHERE id = ?', [id]);
        
        await connection.commit();
        res.json({ message: 'Product deleted successfully.' });
    } catch (error) {
        await connection.rollback();
        console.error("Delete Product Error:", error);
        if (error.code === 'ER_ROW_IS_REFERENCED_2') {
             return res.status(400).json({ message: 'Cannot delete product because it is referenced in past orders.' });
        }
        res.status(500).json({ message: 'Failed to delete product.' });
    } finally {
        connection.release();
    }
});

// --- INVENTORY ROUTES ---
app.get('/api/inventory', verifyToken, hasPermission(['inventory']), async (req, res) => {
    try {
        const [items] = await db.query(`
            SELECT p.id as product_id, p.name, COALESCE(i.stock_quantity, 0) as stock_quantity,
            CASE
                WHEN COALESCE(i.stock_quantity, 0) = 0 THEN 'Out of Stock'
                WHEN COALESCE(i.stock_quantity, 0) <= 10 THEN 'Low Stock'
                ELSE 'In Stock'
            END as status
            FROM products p
            LEFT JOIN inventory i ON p.id = i.product_id
            ORDER BY p.name ASC;
        `);
        res.json(items);
    } catch(error) {
        console.error("Fetch Inventory Error:", error);
        res.status(500).json({ message: 'Failed to fetch inventory.'});
    }
});

app.put('/api/inventory/:productId', verifyToken, hasPermission(['inventory']), async (req, res) => {
    const { productId } = req.params;
    const { newStock } = req.body;
    
    if (newStock === undefined || newStock < 0) {
        return res.status(400).json({ message: 'Valid stock quantity is required.' });
    }
    
    try {
        const [existing] = await db.query('SELECT * FROM inventory WHERE product_id = ?', [productId]);
        
        if (existing.length === 0) {
            await db.query('INSERT INTO inventory (product_id, stock_quantity) VALUES (?, ?)', [productId, newStock]);
        } else {
            await db.query('UPDATE inventory SET stock_quantity = ? WHERE product_id = ?', [newStock, productId]);
        }
        
        res.json({ message: 'Stock updated successfully.' });
    } catch (error) {
        console.error("Update Stock Error:", error);
        res.status(500).json({ message: 'Failed to update stock.' });
    }
});

// --- ORDER ROUTES ---
app.post('/api/orders', verifyToken, hasPermission(['pos']), async (req, res) => {
    const { cart, totalAmount, customerName, discount, officialReceiptNo, source } = req.body;
    const agentId = req.user.id;
    if (!cart || cart.length === 0) return res.status(400).json({ message: 'Cart cannot be empty.' });

    const connection = await db.getConnection();
    try {
        await connection.beginTransaction();
        
        const [orderResult] = await connection.query(
            'INSERT INTO orders (agent_id, total_amount, customer_name, discount, source, status, payment_status, official_receipt_no) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
            [agentId, totalAmount, customerName || 'Walk-in', discount || 0, source || 'pos', 'Completed', 'Paid', officialReceiptNo]
        );
        const orderId = orderResult.insertId;

        for (const item of cart) {
            await connection.query(
                'INSERT INTO order_items (order_id, product_id, quantity, price_per_unit) VALUES (?, ?, ?, ?)', 
                [orderId, item.id, item.quantity, item.price]
            );
            
            const [stock] = await connection.query('SELECT stock_quantity FROM inventory WHERE product_id = ? FOR UPDATE', [item.id]);
            if (stock.length === 0 || stock[0].stock_quantity < item.quantity) {
                throw new Error(`Insufficient stock for product: ${item.name}`);
            }
            await connection.query('UPDATE inventory SET stock_quantity = stock_quantity - ? WHERE product_id = ?', [item.quantity, item.id]);
        }

        await connection.commit();
        res.status(201).json({ message: 'Order created successfully!', orderId });
    } catch (error) {
        await connection.rollback();
        console.error("Create Order Error:", error);
        res.status(500).json({ message: error.message || 'Failed to create order.' });
    } finally {
        connection.release();
    }
});

// --- Corrected and Enhanced Order Fetching Route ---
// This version adds detailed logging to help pinpoint the exact error.
app.get('/api/orders', verifyToken, hasPermission(['orders']), async (req, res) => {
    try {
        console.log("Attempting to fetch orders from the database...");

        // This query explicitly lists columns to be more stable.
        const query = `
            SELECT
                o.id,
                o.agent_id,
                o.total_amount,
                o.customer_name,
                o.discount,
                o.source,
                o.status,
                o.payment_status,
                o.official_receipt_no,
                o.order_date,
                COALESCE(u.username, 'N/A') as agent_name
            FROM
                orders o
            LEFT JOIN
                users u ON o.agent_id = u.id
            ORDER BY
                o.order_date DESC
        `;
        const [orders] = await db.query(query);
        console.log(`Successfully fetched ${orders.length} orders from the database.`);

        const mappedOrders = orders.map(o => ({
            ...o,
            total_amount: parseFloat(o.total_amount),
            discount: parseFloat(o.discount || 0)
        }));

        res.json(mappedOrders);

    } catch (error) {
        // This will print a very detailed error message in your server's terminal
        console.error("--- DATABASE ERROR in GET /api/orders ---");
        console.error("Timestamp:", new Date().toISOString());
        console.error("Error Code:", error.code);
        console.error("Error Message:", error.message);
        console.error("--- END DATABASE ERROR ---");
        res.status(500).json({ message: "Failed to fetch orders. Check server logs for details." });
    }
});

app.get('/api/orders/:id', verifyToken, hasPermission(['orders']), async (req, res) => {
    const { id } = req.params;
    try {
        const [orderQuery] = await db.query(`
            SELECT o.*, u.username as agent_name
            FROM orders o
            LEFT JOIN users u ON o.agent_id = u.id
            WHERE o.id = ?
        `, [id]);
        
        if (orderQuery.length === 0) {
            return res.status(404).json({ message: 'Order not found.' });
        }
        
        const [itemsQuery] = await db.query(`
            SELECT oi.*, p.name
            FROM order_items oi
            JOIN products p ON oi.product_id = p.id
            WHERE oi.order_id = ?
        `, [id]);
        
        const order = {
            ...orderQuery[0],
            total_amount: parseFloat(orderQuery[0].total_amount),
            discount: parseFloat(orderQuery[0].discount || 0),
            items: itemsQuery.map(item => ({
                ...item,
                price_per_unit: parseFloat(item.price_per_unit)
            }))
        };
        
        res.json(order);
    } catch (error) {
        console.error("Fetch Order Details Error:", error);
        res.status(500).json({ message: "Failed to fetch order details." });
    }
});

app.put('/api/orders/:id/status', verifyToken, hasPermission(['orders']), async (req, res) => {
    const { id } = req.params;
    const { status } = req.body;
    
    const validStatuses = ['Pending', 'Confirmed', 'Preparing', 'Out for Delivery', 'Completed', 'Cancelled'];
    if (!validStatuses.includes(status)) {
        return res.status(400).json({ message: 'Invalid status.' });
    }
    
    try {
        await db.query('UPDATE orders SET status = ? WHERE id = ?', [status, id]);
        res.json({ message: 'Order status updated successfully.' });
    } catch (error) {
        console.error("Update Order Status Error:", error);
        res.status(500).json({ message: 'Failed to update order status.' });
    }
});

// --- REPORTING ROUTES ---
app.get('/api/sales/summary', verifyToken, hasPermission(['dashboard']), async (req, res) => {
    try {
        const [summary] = await db.query(`
            SELECT 
                COALESCE(SUM(total_amount), 0) as totalRevenue,
                COUNT(id) as totalOrders
            FROM orders 
            WHERE order_date >= CURDATE() - INTERVAL 7 DAY AND status = 'Completed';
        `);
        
        const [dailySales] = await db.query(`
            SELECT 
                DATE_FORMAT(order_date, '%a') as day,
                COALESCE(SUM(total_amount), 0) as sales
            FROM orders 
            WHERE order_date >= CURDATE() - INTERVAL 7 DAY AND status = 'Completed'
            GROUP BY DATE(order_date), DATE_FORMAT(order_date, '%a')
            ORDER BY DATE(order_date);
        `);
        
        const [topProducts] = await db.query(`
            SELECT p.name, SUM(oi.quantity) as total_quantity
            FROM order_items oi
            JOIN products p ON oi.product_id = p.id
            JOIN orders o ON o.id = oi.order_id
            WHERE o.order_date >= CURDATE() - INTERVAL 30 DAY AND o.status = 'Completed'
            GROUP BY p.name
            ORDER BY total_quantity DESC
            LIMIT 5;
        `);

        const weekDays = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
        const salesData = new Map(dailySales.map(d => [d.day, parseFloat(d.sales)]));
        const salesByDay = weekDays.map(day => salesData.get(day) || 0);

        res.json({
            summary: {
                totalRevenue: parseFloat(summary[0].totalRevenue || 0),
                totalOrders: summary[0].totalOrders || 0
            },
            dailySales: { labels: weekDays, data: salesByDay },
            topProducts: topProducts || []
        });
    } catch (error) {
        console.error("Sales summary error:", error);
        res.status(500).json({ message: "Failed to fetch sales summary." });
    }
});

// --- FIX EXISTING PERMISSIONS DATA ---
const fixExistingPermissions = async () => {
    try {
        console.log('Checking and fixing existing permissions data...');
        
        const [users] = await db.query('SELECT id, username, permissions FROM users');
        
        for (const user of users) {
            const currentPermissions = user.permissions;
            const parsedPermissions = parsePermissions(currentPermissions);
            
            // Only update if the current permissions are invalid JSON or need fixing
            if (typeof currentPermissions === 'string' && currentPermissions !== JSON.stringify(parsedPermissions)) {
                await db.query(
                    'UPDATE users SET permissions = ? WHERE id = ?',
                    [JSON.stringify(parsedPermissions), user.id]
                );
                console.log(`Fixed permissions for user: ${user.username}`);
            }
        }
        
        console.log('Permissions data check completed.');
    } catch (error) {
        console.error('Error fixing permissions data:', error);
    }
};

// --- DATABASE INITIALIZATION ---
const initializeDatabase = async () => {
    try {
        await db.query(`
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                role ENUM('Super Admin', 'Admin', 'Agent') DEFAULT 'Agent',
                permissions JSON,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        await db.query(`
            CREATE TABLE IF NOT EXISTS products (
                id INT AUTO_INCREMENT PRIMARY KEY,
                name VARCHAR(100) NOT NULL,
                description TEXT,
                price DECIMAL(10,2) NOT NULL,
                image_url VARCHAR(255),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        await db.query(`
            CREATE TABLE IF NOT EXISTS inventory (
                id INT AUTO_INCREMENT PRIMARY KEY,
                product_id INT NOT NULL,
                stock_quantity INT DEFAULT 0,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE CASCADE
            )
        `);

        await db.query(`
            CREATE TABLE IF NOT EXISTS orders (
                id INT AUTO_INCREMENT PRIMARY KEY,
                agent_id INT NOT NULL,
                total_amount DECIMAL(10,2) NOT NULL,
                customer_name VARCHAR(100),
                discount DECIMAL(10,2) DEFAULT 0,
                source ENUM('pos', 'online', 'mobile') DEFAULT 'pos',
                status ENUM('Pending', 'Confirmed', 'Preparing', 'Out for Delivery', 'Completed', 'Cancelled') DEFAULT 'Pending',
                payment_status ENUM('Pending', 'Paid', 'Refunded') DEFAULT 'Pending',
                official_receipt_no VARCHAR(50),
                order_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (agent_id) REFERENCES users(id)
            )
        `);

        await db.query(`
            CREATE TABLE IF NOT EXISTS order_items (
                id INT AUTO_INCREMENT PRIMARY KEY,
                order_id INT NOT NULL,
                product_id INT,
                quantity INT NOT NULL,
                price_per_unit DECIMAL(10,2) NOT NULL,
                FOREIGN KEY (order_id) REFERENCES orders(id) ON DELETE CASCADE,
                FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE SET NULL
            )
        `);

        const [existingAdmin] = await db.query("SELECT id FROM users WHERE role = 'Super Admin' LIMIT 1");
        if (existingAdmin.length === 0) {
            const hashedPassword = await bcrypt.hash('admin123', saltRounds);
            await db.query(
                "INSERT INTO users (username, password, role, permissions) VALUES (?, ?, ?, ?)",
                ['superadmin', hashedPassword, 'Super Admin', JSON.stringify([])]
            );
            console.log('Default Super Admin created: username=superadmin, password=admin123');
        }

        // Fix any existing permissions data issues
        await fixExistingPermissions();

        console.log('Database initialized successfully');
    } catch (error) {
        console.error('Database initialization error:', error);
        process.exit(1);
    }
};

// Initialize database on startup then start the server
initializeDatabase().then(() => {
    app.listen(port, () => {
        console.log(`Bughaw Admin Server is live on http://localhost:${port}`);
    });
});