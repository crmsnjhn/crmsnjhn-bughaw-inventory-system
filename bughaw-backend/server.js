/*
================================================================================
-- BUGHWAW MULTI-LINE CORP - BACKEND API (V12.2 - HIERARCHICAL PERMISSIONS) --
================================================================================
This is the final, complete server code with the new "Sub-Admin" role,
granular per-user permissions, and a hierarchical user management system.
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
require('dotenv').config();
const app = express();
const port = process.env.PORT || 5000;
const saltRounds = 10;
const JWT_SECRET = process.env.JWT_SECRET;

const db = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    waitForConnections: true,
    connectionLimit: 15,
    queueLimit: 0,
    dateStrings: true,
    timezone: '+08:00'
}).promise();

app.use(cors());
app.use(express.json());

const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir);
app.use('/uploads', express.static(uploadsDir));

const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, 'uploads/'),
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
    }
});
const upload = multer({ storage: storage, limits: { fileSize: 5 * 1024 * 1024 } });

// --- AUTH MIDDLEWARE ---
const verifyToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ message: "Unauthorized: No token provided." });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            if (err.name === 'TokenExpiredError') return res.status(401).json({ message: 'Token expired. Please log in again.' });
            return res.status(403).json({ message: "Forbidden: Invalid token." });
        }
        req.user = user;
        next();
    });
};

const hasPermission = (requiredPermissions) => async (req, res, next) => {
    const userPermissions = req.user.permissions || [];
    const permsToCheck = Array.isArray(requiredPermissions) ? requiredPermissions : [requiredPermissions];
    const hasAtLeastOnePerm = permsToCheck.some(p => userPermissions.includes(p));

    if (hasAtLeastOnePerm) {
        next();
    } else {
        return res.status(403).json({ message: `Forbidden: Missing required permission: ${permsToCheck.join(', ')}` });
    }
};

// ================================================================================
// --- API ROUTES ---
// ================================================================================

// ## AUTHENTICATION ##
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ message: 'Username and password are required.' });
    try {
        const userQuery = `SELECT u.*, b.name as branch_name, b.is_main_branch FROM users u LEFT JOIN branches b ON u.branch_id = b.id WHERE u.username = ? AND u.is_active = TRUE`;
        const [users] = await db.query(userQuery, [username]);
        if (users.length === 0) return res.status(401).json({ message: 'Invalid credentials or account is disabled.' });

        const user = users[0];
        const isPasswordMatch = await bcrypt.compare(password, user.password);
        if (!isPasswordMatch) return res.status(401).json({ message: 'Invalid credentials.' });

        const rolePermsQuery = `SELECT p.name as permission_name FROM user_roles ur JOIN role_permissions rp ON ur.role_id = rp.role_id JOIN permissions p ON rp.permission_id = p.id WHERE ur.user_id = ?`;
        const [rolePermissions] = await db.query(rolePermsQuery, [user.id]);
        
        const specificPermsQuery = `SELECT p.name as permission_name FROM user_specific_permissions usp JOIN permissions p ON usp.permission_id = p.id WHERE usp.user_id = ?`;
        const [specificPermissions] = await db.query(specificPermsQuery, [user.id]);

        const allPermissions = new Set([
            ...rolePermissions.map(p => p.permission_name),
            ...specificPermissions.map(p => p.permission_name)
        ]);
        
        const [roles] = await db.query(`SELECT r.name as role_name FROM user_roles ur JOIN roles r ON ur.role_id = r.id WHERE ur.user_id = ?`, [user.id]);

        const userPayload = {
            id: user.id,
            username: user.username,
            role: roles.length > 0 ? roles[0].role_name : 'No Role',
            branch_id: user.branch_id,
            branch_name: user.branch_name || 'All Branches',
            is_main_branch: user.is_main_branch || false,
            permissions: [...allPermissions]
        };
        const token = jwt.sign(userPayload, JWT_SECRET, { expiresIn: '8h' });
        res.json({ token, user: userPayload });
    } catch (error) {
        console.error("Login Error:", error);
        res.status(500).json({ message: 'Server error during login process.' });
    }
});

// ## BRANCH MANAGEMENT ##
app.get('/api/branches', verifyToken, hasPermission('manage_users'), async (req, res) => {
    try {
        const [branches] = await db.query('SELECT * FROM branches ORDER BY name');
        res.json(branches);
    } catch (error) {
        console.error("Error fetching branches:", error);
        res.status(500).json({ message: "Failed to fetch branches." });
    }
});

app.post('/api/branches', verifyToken, hasPermission('manage_branches'), async (req, res) => {
    const { name, is_main_branch } = req.body;
    if (!name || name.trim() === '') return res.status(400).json({ message: 'Branch name is required.' });
    const connection = await db.getConnection();
    try {
        await connection.beginTransaction();
        if (is_main_branch) await connection.query('UPDATE branches SET is_main_branch = FALSE WHERE is_main_branch = TRUE');
        await connection.query('INSERT INTO branches (name, is_main_branch) VALUES (?, ?)', [name.trim(), is_main_branch || false]);
        await connection.commit();
        res.status(201).json({ message: 'Branch created successfully.' });
    } catch (error) {
        await connection.rollback();
        if (error.code === 'ER_DUP_ENTRY') return res.status(409).json({ message: 'A branch with this name already exists.' });
        res.status(500).json({ message: 'Failed to create branch.' });
    } finally {
        connection.release();
    }
});

// ## USER MANAGEMENT ##
app.get('/api/users', verifyToken, hasPermission('manage_users'), async (req, res) => {
    const requestingUser = req.user;
    let query = `
        SELECT u.id, u.username, u.branch_id, b.name as branch_name, r.name as role, u.is_active
        FROM users u
        LEFT JOIN branches b ON u.branch_id = b.id
        LEFT JOIN user_roles ur ON u.id = ur.user_id
        LEFT JOIN roles r ON ur.role_id = r.id
        WHERE (r.name != 'Super Admin' OR r.name IS NULL)
    `;
    const queryParams = [];

    if (requestingUser.role === 'Admin') {
        query += ' AND u.created_by = ?';
        queryParams.push(requestingUser.id);
    }
    
    const [users] = await db.query(query, queryParams);
    res.json(users);
});

app.post('/api/users/register', verifyToken, hasPermission('manage_users'), async (req, res) => {
    const { username, password, role_id, branch_id, permissions } = req.body;
    if (!username || !password || !role_id) return res.status(400).json({ message: 'Username, password, and role are required.' });
    
    const creator = req.user;
    const connection = await db.getConnection();

    try {
        await connection.beginTransaction();
        const [creatorData] = await connection.query('SELECT * FROM users WHERE id = ?', [creator.id]);
        const creatorLimits = creatorData[0];
        const [targetRole] = await connection.query('SELECT name FROM roles WHERE id = ?', [role_id]);
        const isCreatingAgent = targetRole[0].name === 'Agent';
        const isCreatingAdmin = targetRole[0].name === 'Admin' || targetRole[0].name === 'Sub-Admin';
        
        const [childCounts] = await connection.query(`SELECT SUM(CASE WHEN r.name = 'Agent' THEN 1 ELSE 0 END) as agent_count, SUM(CASE WHEN r.name IN ('Admin', 'Sub-Admin') THEN 1 ELSE 0 END) as admin_count FROM users u JOIN user_roles ur ON u.id = ur.user_id JOIN roles r ON ur.role_id = r.id WHERE u.created_by = ?`, [creator.id]);

        if (isCreatingAgent && childCounts[0].agent_count >= creatorLimits.max_agents) {
            await connection.rollback();
            return res.status(403).json({ message: `Maximum agent accounts reached (${creatorLimits.max_agents}).` });
        }
        
        if (isCreatingAdmin && childCounts[0].admin_count >= creatorLimits.max_admins) {
            await connection.rollback();
            return res.status(403).json({ message: `Maximum admin accounts reached (${creatorLimits.max_admins}).` });
        }

        const hashedPassword = await bcrypt.hash(password, saltRounds);
        const [newUserResult] = await connection.query('INSERT INTO users (username, password, branch_id, created_by) VALUES (?, ?, ?, ?)', [username, hashedPassword, branch_id, creator.id]);
        const newUserId = newUserResult.insertId;
        
        await connection.query('INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)', [newUserId, role_id]);

        if (permissions && permissions.length > 0) {
            const permissionValues = permissions.map(permId => [newUserId, permId]);
            await connection.query('INSERT INTO user_specific_permissions (user_id, permission_id) VALUES ?', [permissionValues]);
        }
        
        await connection.commit();
        res.status(201).json({ message: 'User created successfully.' });
    } catch (error) {
        await connection.rollback();
        if (error.code === 'ER_DUP_ENTRY') return res.status(409).json({ message: 'Username already exists.' });
        console.error("User Registration Error:", error);
        res.status(500).json({ message: 'Failed to create user.' });
    } finally {
        connection.release();
    }
});


app.get('/api/roles', verifyToken, hasPermission('manage_users'), async (req, res) => {
    try {
        let query = "SELECT * FROM roles";
        if (req.user.role === 'Super Admin') {
            query += " WHERE name = 'Admin'";
        } else {
            query += " WHERE name IN ('Sub-Admin', 'Agent')";
        }
        const [roles] = await db.query(query);
        res.json(roles);
    } catch (error) {
        console.error("Error fetching roles:", error);
        res.status(500).json({ message: 'Failed to fetch roles.' });
    }
});

app.get('/api/permissions', verifyToken, hasPermission('manage_users'), async (req, res) => {
    try {
        const query = `SELECT * FROM permissions WHERE name NOT IN ('manage_users', 'manage_branches')`;
        const [permissions] = await db.query(query);
        res.json(permissions);
    } catch (error) {
        console.error("Error fetching permissions:", error);
        res.status(500).json({ message: 'Failed to fetch permissions.' });
    }
});

app.post('/api/users/:id/limits', verifyToken, hasPermission('manage_users'), async (req, res) => {
    const { max_agents, max_admins } = req.body;
    const userIdToUpdate = req.params.id;
    try {
        await db.query('UPDATE users SET max_agents = ?, max_admins = ? WHERE id = ?', [max_agents, max_admins, userIdToUpdate]);
        res.json({ message: 'User limits updated successfully.' });
    } catch (error) {
        console.error("Error setting user limits:", error);
        res.status(500).json({ message: 'Failed to update user limits.' });
    }
});


app.get('/api/agents', verifyToken, hasPermission('manage_customers'), async (req, res) => {
    try {
        const query = `SELECT u.id, u.username FROM users u JOIN user_roles ur ON u.id = ur.user_id WHERE ur.role_id = (SELECT id FROM roles WHERE name = 'Agent')`; 
        const [agents] = await db.query(query);
        res.json(agents);
    } catch (error) {
        console.error("Error fetching agents:", error);
        res.status(500).json({ message: 'Failed to fetch agents.' });
    }
});


// ## CUSTOMER MANAGEMENT ##
app.get('/api/customers', verifyToken, hasPermission('manage_customers'), async (req, res) => {
    try {
        const query = `SELECT c.*, u.username as agent_name, d.name as price_level_name, b.name as branch_name FROM customers c LEFT JOIN users u ON c.agent_id = u.id LEFT JOIN discounts d ON c.price_level_id = d.id LEFT JOIN branches b ON c.branch_id = b.id WHERE c.branch_id = ? ORDER BY c.name`;
        const [customers] = await db.query(query, [req.user.branch_id]);
        res.json(customers);
    } catch (error) {
        console.error("Error fetching customers:", error);
        res.status(500).json({ message: 'Failed to fetch customers.' });
    }
});

app.get('/api/customers/:customerId/check-pending', verifyToken, hasPermission('use_pos'), async (req, res) => {
    const { customerId } = req.params;
    try {
        const query = `SELECT id, invoice_no FROM orders WHERE customer_id = ? AND payment_status = 'Unpaid' AND status != 'Cancelled' LIMIT 1`;
        const [unpaidOrders] = await db.query(query, [customerId]);
        if (unpaidOrders.length > 0) {
            res.json({ has_pending: true, order_info: unpaidOrders[0] });
        } else {
            res.json({ has_pending: false, order_info: null });
        }
    } catch (error) {
        console.error("Error checking pending customer payments:", error);
        res.status(500).json({ message: 'Failed to check pending payments.' });
    }
});

app.post('/api/customers', verifyToken, hasPermission('manage_customers'), async (req, res) => {
    const { name, address, agent_id, contact_number_1, contact_number_2, payment_terms, price_level_id, freight_duration, credit_limit } = req.body;
    if (!name) return res.status(400).json({ message: "Customer name is required." });
    const branch_id = req.user.branch_id;
    if (!branch_id) return res.status(400).json({ message: "Your account is not assigned to a branch." });

    const customer_code = `CUST-${Date.now()}`;
    try {
        await db.query(`INSERT INTO customers (customer_code, name, address, agent_id, contact_number_1, contact_number_2, payment_terms, price_level_id, freight_duration, credit_limit, branch_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [customer_code, name, address || null, agent_id || null, contact_number_1 || null, contact_number_2 || null, payment_terms || 30, price_level_id || null, freight_duration || 5, credit_limit || 0, branch_id]);
        res.status(201).json({ message: "Customer registered successfully." });
    } catch (error) {
        console.error("Error registering customer:", error);
        res.status(500).json({ message: "Failed to register customer due to a server error." });
    }
});

// ## PRICING ENGINE ##
app.post('/api/pricing/calculate', verifyToken, hasPermission('use_pos'), async (req, res) => {
    const { cart, customer_id } = req.body;
    if (!cart || cart.length === 0) return res.json([]);
    try {
        let customerPriceLevelId = null;
        if (customer_id) {
            const [customer] = await db.query('SELECT price_level_id FROM customers WHERE id = ?', [customer_id]);
            if (customer.length > 0) customerPriceLevelId = customer[0].price_level_id;
        }

        const [discounts] = await db.query('SELECT * FROM discounts WHERE is_active = TRUE');
        
        const pricedCart = cart.map(item => {
            let finalPrice = parseFloat(item.price);
            let appliedDiscount = null;

            if (item.discount && parseFloat(item.discount) > 0) {
                finalPrice -= parseFloat(item.discount);
                appliedDiscount = { name: `Manual Discount` };
            } 
            else if (customerPriceLevelId) {
                const customerDiscount = discounts.find(d => d.id === customerPriceLevelId);
                if (customerDiscount) {
                    if (customerDiscount.type === 'PERCENTAGE') finalPrice *= (1 - customerDiscount.value / 100);
                    else finalPrice -= customerDiscount.value;
                    appliedDiscount = customerDiscount;
                }
            }
            
            return { ...item, originalPrice: parseFloat(item.price), finalPrice: Math.max(0, finalPrice), appliedDiscount };
        });

        res.json(pricedCart);
    } catch (error) {
        console.error("Pricing calculation error:", error);
        res.status(500).json({ message: 'Error calculating prices.' });
    }
});


// ## PRODUCT MANAGEMENT ##
app.get('/api/products', verifyToken, hasPermission(['manage_products', 'use_pos']), async (req, res) => {
    const { page = 0, pageSize = 100, search = '' } = req.query;
    const offset = parseInt(page, 10) * parseInt(pageSize, 10);
    let whereClauses = ['p.is_active = TRUE'];
    const queryParams = [];
    if (search) {
        whereClauses.push(`(p.name LIKE ? OR p.category LIKE ?)`);
        queryParams.push(`%${search}%`, `%${search}%`);
    }
    const whereString = `WHERE ${whereClauses.join(' AND ')}`;
    const dataQuery = `SELECT p.*, pa.name as partner_name, COALESCE(i.stock_quantity, 0) as stock FROM products p LEFT JOIN inventory i ON p.id = i.product_id LEFT JOIN partners pa ON p.partner_id = pa.id ${whereString} ORDER BY p.name LIMIT ? OFFSET ?`;
    const [products] = await db.query(dataQuery, [...queryParams, parseInt(pageSize, 10), offset]);
    const countQuery = `SELECT COUNT(p.id) as total FROM products p ${whereString}`;
    const [totalRows] = await db.query(countQuery, queryParams);
    res.json({
        rows: products.map(p => ({ ...p, price: parseFloat(p.price) })),
        rowCount: totalRows[0].total
    });
});

app.post('/api/products', verifyToken, hasPermission('manage_products'), upload.single('image'), async (req, res) => {
    const { name, description, price, partner_id, category, unit } = req.body;
    const imageUrl = req.file ? `/${req.file.path.replace(/\\/g, "/")}` : null;

    if (!name || !price) {
        return res.status(400).json({ message: 'Product name and price are required.' });
    }

    const connection = await db.getConnection();
    try {
        await connection.beginTransaction();

        const [productResult] = await connection.query('INSERT INTO products (name, description, price, partner_id, category, unit, image_url) VALUES (?, ?, ?, ?, ?, ?, ?)', [name, description || null, price, partner_id || null, category || null, unit || 'pcs', imageUrl]);
        const newProductId = productResult.insertId;

        await connection.query('INSERT INTO inventory (product_id, stock_quantity) VALUES (?, ?)', [newProductId, 0]);

        await connection.commit();
        res.status(201).json({ message: 'Product created successfully.' });
    } catch (error) {
        await connection.rollback();
        console.error("Error creating product:", error);
        res.status(500).json({ message: 'Failed to create product.' });
    } finally {
        connection.release();
    }
});


// ## INVENTORY MANAGEMENT ##
app.get('/api/inventory', verifyToken, hasPermission('manage_inventory'), async (req, res) => {
    try {
        const query = `SELECT p.id as product_id, p.name, p.category, pa.name as partner_name, i.stock_quantity, CASE WHEN i.stock_quantity <= 0 THEN 'Out of Stock' WHEN i.stock_quantity <= 10 THEN 'Low Stock' ELSE 'In Stock' END as status FROM products p JOIN inventory i ON p.id = i.product_id LEFT JOIN partners pa ON p.partner_id = pa.id ORDER BY p.name`;
        const [inventory] = await db.query(query);
        res.json(inventory);
    } catch (error) {
        console.error("Error fetching inventory:", error);
        res.status(500).json({ message: "Failed to fetch inventory." });
    }
});

app.put('/api/inventory/:productId', verifyToken, hasPermission('manage_inventory'), async (req, res) => {
    const { productId } = req.params;
    const { newStock } = req.body;

    if (newStock === undefined || newStock < 0) {
        return res.status(400).json({ message: 'A valid new stock quantity is required.' });
    }

    try {
        await db.query('UPDATE inventory SET stock_quantity = ? WHERE product_id = ?', [newStock, productId]);
        res.json({ message: 'Stock updated successfully.' });
    } catch (error) {
        console.error("Error updating stock:", error);
        res.status(500).json({ message: 'Failed to update stock quantity.' });
    }
});


// ## DISCOUNT MANAGEMENT ##
app.get('/api/discounts', verifyToken, hasPermission(['manage_discounts', 'manage_customers', 'use_pos']), async (req, res) => {
    try {
        const [discounts] = await db.query('SELECT * FROM discounts ORDER BY name');
        res.json(discounts);
    } catch (error) {
        console.error("Error fetching discounts:", error);
        res.status(500).json({ message: "Failed to fetch discounts." });
    }
});

app.post('/api/discounts/advanced', verifyToken, hasPermission('manage_discounts'), async (req, res) => {
    const { name, type, value, assignments } = req.body;
    if (!name || !type || !value) return res.status(400).json({ message: "Name, type, and value are required." });

    const connection = await db.getConnection();
    try {
        await connection.beginTransaction();

        const [discountResult] = await connection.query('INSERT INTO discounts (name, type, value) VALUES (?, ?, ?)', [name, type, value]);
        const discountId = discountResult.insertId;

        if (assignments && assignments.length > 0) {
            const assignmentValues = assignments.map(a => [discountId, a.id]);
            await connection.query('INSERT INTO discount_product_assignments (discount_id, product_id) VALUES ?', [assignmentValues]);
        }
        
        await connection.commit();
        res.status(201).json({ message: 'Advanced discount rule created successfully.' });
    } catch (error) {
        await connection.rollback();
        console.error("Error creating advanced discount:", error);
        res.status(500).json({ message: 'Failed to create discount rule.' });
    } finally {
        connection.release();
    }
});

// ## PARTNER MANAGEMENT ##
app.get('/api/partners', verifyToken, hasPermission('manage_products'), async (req, res) => {
    try {
        const [partners] = await db.query('SELECT * FROM partners ORDER BY name');
        res.json(partners);
    } catch (error) {
        console.error("Error fetching partners:", error);
        res.status(500).json({ message: 'Failed to fetch partners.' });
    }
});

app.post('/api/partners', verifyToken, hasPermission('manage_products'), async (req, res) => {
    const { name } = req.body;
    if (!name || name.trim() === '') return res.status(400).json({ message: 'Partner name is required.' });
    try {
        await db.query('INSERT INTO partners (name) VALUES (?)', [name.trim()]);
        res.status(201).json({ message: 'Partner created successfully.' });
    } catch (error) {
        if (error.code === 'ER_DUP_ENTRY') return res.status(409).json({ message: 'A partner with this name already exists.' });
        res.status(500).json({ message: 'Failed to create partner.' });
    }
});


// ## ORDER MANAGEMENT ##
app.get('/api/orders', verifyToken, hasPermission('manage_orders'), async (req, res) => {
    try {
        let query = `SELECT o.*, c.name as customer_name, u.username as agent_name FROM orders o JOIN customers c ON o.customer_id = c.id JOIN users u ON o.agent_id = u.id WHERE o.status NOT IN ('Delivered', 'Completed', 'Cancelled')`;
        const queryParams = [];
        if (req.user.branch_id) {
            query += ` AND o.branch_id = ?`;
            queryParams.push(req.user.branch_id);
        }
        query += ' ORDER BY o.order_date DESC';
        const [orders] = await db.query(query, queryParams);
        res.json(orders);
    } catch (error) {
        console.error("Error fetching active orders:", error);
        res.status(500).json({ message: "Failed to fetch active orders." });
    }
});

app.get('/api/orders/:id', verifyToken, hasPermission(['manage_orders', 'use_pos']), async (req, res) => {
    const { id } = req.params;
    try {
        const orderQuery = `SELECT o.*, c.name as customer_name, u.username as agent_name FROM orders o JOIN customers c ON o.customer_id = c.id JOIN users u ON o.agent_id = u.id WHERE o.id = ?`;
        const [orders] = await db.query(orderQuery, [id]);
        
        if (orders.length === 0) {
            return res.status(404).json({ message: 'Order not found.' });
        }

        const itemsQuery = `SELECT oi.*, p.name FROM order_items oi JOIN products p ON oi.product_id = p.id WHERE oi.order_id = ?`;
        const [items] = await db.query(itemsQuery, [id]);
        
        const orderDetails = { ...orders[0], items: items };
        res.json(orderDetails);
    } catch (error) {
        console.error("Error fetching order details:", error);
        res.status(500).json({ message: "Failed to fetch order details." });
    }
});


app.post('/api/orders', verifyToken, hasPermission('use_pos'), async (req, res) => {
    const { customer, cart, payment_type, source } = req.body;
    const agentId = req.user.id;
    const branchId = req.user.branch_id;

    if (!customer || !cart || cart.length === 0) {
        return res.status(400).json({ message: 'Customer and cart information are required.' });
    }

    const connection = await db.getConnection();
    try {
        await connection.beginTransaction();
        
        let customerId = customer.id;
        if (!customerId) {
            const customer_code = `CUST-${Date.now()}`;
            const [newCustomer] = await connection.query(`INSERT INTO customers (customer_code, name, address, contact_number_1, agent_id, branch_id) VALUES (?, ?, ?, ?, ?, ?)`, [customer_code, customer.name, customer.address || null, customer.contact_number_1 || null, agentId, branchId]);
            customerId = newCustomer.insertId;
        }

        const total_amount = cart.reduce((sum, item) => sum + (item.price * item.quantity), 0);
        const total_discount = cart.reduce((sum, item) => sum + ((item.discount_per_unit || 0) * item.quantity), 0);
        const final_amount = total_amount - total_discount;

        const payment_status = payment_type === 'COD' ? 'Paid' : 'Unpaid';
        const [orderResult] = await connection.query(`INSERT INTO orders (agent_id, customer_id, total_amount, discount, source, payment_status, branch_id) VALUES (?, ?, ?, ?, ?, ?, ?)`, [agentId, customerId, final_amount, total_discount, source || 'pos', payment_status, branchId]);
        const orderId = orderResult.insertId;

        for (const item of cart) {
            await connection.query('INSERT INTO order_items (order_id, product_id, quantity, price_per_unit, discount_per_unit) VALUES (?, ?, ?, ?, ?)', [orderId, item.id, item.quantity, item.price, item.discount_per_unit || 0]);
            await connection.query('UPDATE inventory SET stock_quantity = stock_quantity - ? WHERE product_id = ?', [item.quantity, item.id]);
        }

        await connection.commit();
        res.status(201).json({ message: 'Order created successfully.', orderId: orderId });
    } catch (error) {
        await connection.rollback();
        console.error("Error creating order:", error);
        res.status(500).json({ message: "Failed to create order." });
    } finally {
        connection.release();
    }
});

app.put('/api/orders/:id/invoice', verifyToken, hasPermission('manage_orders'), async (req, res) => {
    const { id } = req.params;
    const { invoiceNo } = req.body;

    if (!invoiceNo) {
        return res.status(400).json({ message: "Invoice number is required." });
    }

    try {
        await db.query(`UPDATE orders SET invoice_no = ?, status = 'Printing' WHERE id = ?`, [invoiceNo, id]);
        res.json({ message: "Invoice number saved and status updated." });
    } catch (error) {
        console.error("Error saving invoice:", error);
        res.status(500).json({ message: "Failed to save invoice." });
    }
});


app.put('/api/orders/:orderId/status', verifyToken, hasPermission(['use_pos', 'manage_orders']), async (req, res) => {
    const { orderId } = req.params;
    const { status } = req.body;
    
    if (!status) return res.status(400).json({ message: 'New status is required.' });

    try {
        await db.query('UPDATE orders SET status = ? WHERE id = ?', [status, orderId]);
        res.json({ message: `Order #${orderId} status updated to ${status}.` });
    } catch (error) {
        console.error("Error updating order status:", error);
        res.status(500).json({ message: 'Failed to update order status.' });
    }
});


app.put('/api/orders/:orderId/edit', verifyToken, hasPermission('use_pos'), async (req, res) => {
    const { orderId } = req.params;
    const { cart } = req.body;
    const agentId = req.user.id;
    const connection = await db.getConnection();

    try {
        await connection.beginTransaction();

        const [order] = await connection.query('SELECT * FROM orders WHERE id = ?', [orderId]);
        if (order.length === 0 || order[0].agent_id !== agentId) {
            await connection.rollback();
            return res.status(403).json({ message: 'Forbidden: You can only edit your own orders.' });
        }
        if (order[0].status !== 'Pending') {
            await connection.rollback();
            return res.status(403).json({ message: 'Order can no longer be edited.' });
        }

        await connection.query('DELETE FROM order_items WHERE order_id = ?', [orderId]);
        
        let total_amount = 0;
        const orderItems = cart.map(item => {
            const itemTotal = parseFloat(item.price) * item.quantity;
            total_amount += itemTotal;
            return [orderId, item.id, item.quantity, item.price, 0];
        });
        await connection.query('INSERT INTO order_items (order_id, product_id, quantity, price_per_unit, discount_per_unit) VALUES ?', [orderItems]);

        await connection.query('UPDATE orders SET total_amount = ? WHERE id = ?', [total_amount, orderId]);

        await connection.commit();
        res.json({ message: `Order #${orderId} has been updated successfully.` });
    } catch (error) {
        await connection.rollback();
        console.error("Error editing order:", error);
        res.status(500).json({ message: 'Failed to edit order.' });
    } finally {
        connection.release();
    }
});


app.get('/api/order-history', verifyToken, hasPermission('manage_orders'), async (req, res) => {
    try {
        let query = `SELECT o.*, c.name as customer_name, u.username as agent_name FROM orders o JOIN customers c ON o.customer_id = c.id JOIN users u ON o.agent_id = u.id WHERE o.status IN ('Delivered', 'Completed', 'Cancelled')`;
        const queryParams = [];
        if (req.user.branch_id) {
            query += ` AND o.branch_id = ?`;
            queryParams.push(req.user.branch_id);
        }
        query += ' ORDER BY o.order_date DESC';
        const [orders] = await db.query(query, queryParams);
        res.json(orders);
    } catch (error) {
        console.error("Error fetching order history:", error);
        res.status(500).json({ message: "Failed to fetch order history." });
    }
});


// ## ACCOUNTING ##
app.get('/api/accounting/unpaid', verifyToken, hasPermission('manage_accounting'), async (req, res) => {
    try {
        let query = `SELECT o.*, c.name as customer_name, u.username as agent_name FROM orders o JOIN customers c ON o.customer_id = c.id JOIN users u ON o.agent_id = u.id WHERE o.payment_status = 'Unpaid'`;
        const queryParams = [];
        if (req.user.branch_id) {
            query += ` AND o.branch_id = ?`;
            queryParams.push(req.user.branch_id);
        }
        query += ' ORDER BY o.order_date ASC';
        const [orders] = await db.query(query, queryParams);
        res.json(orders);
    } catch (error) {
        console.error("Error fetching unpaid orders:", error);
        res.status(500).json({ message: "Failed to fetch unpaid orders." });
    }
});

app.post('/api/accounting/mark-paid/:orderId', verifyToken, hasPermission('manage_accounting'), async (req, res) => {
    const { orderId } = req.params;
    const { password } = req.body;
    const adminUserId = req.user.id;

    if (!password) {
        return res.status(400).json({ message: "Password is required for authorization." });
    }

    try {
        const [adminUser] = await db.query('SELECT password FROM users WHERE id = ?', [adminUserId]);
        if (adminUser.length === 0) {
            return res.status(401).json({ message: "Unauthorized." });
        }
        const isPasswordMatch = await bcrypt.compare(password, adminUser[0].password);
        if (!isPasswordMatch) {
            return res.status(403).json({ message: "Invalid password. Authorization failed." });
        }

        await db.query(`UPDATE orders SET payment_status = 'Paid', status = 'Completed' WHERE id = ?`, [orderId]);
        res.json({ message: "Order successfully marked as paid." });

    } catch (error) {
        console.error("Error marking order as paid:", error);
        res.status(500).json({ message: "Failed to mark order as paid." });
    }
});


// ## DASHBOARD & REPORTING ##
app.get('/api/sales/summary', verifyToken, hasPermission('view_dashboard'), async (req, res) => {
    const { period = 'weekly' } = req.query;
    const user = req.user;
    let intervalClause, dateFormat;

    switch (period) {
        case 'monthly': intervalClause = 'INTERVAL 1 MONTH'; dateFormat = '%Y-%m-%d'; break;
        case 'daily': intervalClause = 'INTERVAL 24 HOUR'; dateFormat = '%l %p'; break;
        default: intervalClause = 'INTERVAL 7 DAY'; dateFormat = '%a'; break;
    }

    try {
        let branchFilter = '';
        const queryParams = [];
        if (user.branch_id) {
            branchFilter = `AND branch_id = ?`;
            queryParams.push(user.branch_id);
        }

        const summaryQuery = `SELECT COALESCE(SUM(CASE WHEN status != 'Cancelled' THEN total_amount ELSE 0 END), 0) as totalRevenue, COUNT(id) as totalOrders FROM orders WHERE order_date >= CURDATE() - ${intervalClause} ${branchFilter}`;
        const [summaryResult] = await db.query(summaryQuery, queryParams);

        const dailySalesQuery = `SELECT DATE_FORMAT(order_date, ?) as day, COALESCE(SUM(total_amount), 0) as sales FROM orders WHERE order_date >= CURDATE() - ${intervalClause} AND status != 'Cancelled' ${branchFilter} GROUP BY day ORDER BY MIN(order_date)`;
        const [dailySalesResult] = await db.query(dailySalesQuery, [dateFormat, ...queryParams]);

        const topProductsQuery = `SELECT p.name, SUM(oi.quantity) as total_quantity FROM order_items oi JOIN products p ON oi.product_id = p.id JOIN orders o ON o.id = oi.order_id WHERE o.status != 'Cancelled' AND o.order_date >= CURDATE() - INTERVAL 30 DAY ${branchFilter} GROUP BY p.name ORDER BY total_quantity DESC LIMIT 10`;
        const [topProductsResult] = await db.query(topProductsQuery, queryParams);

        const salesData = { labels: dailySalesResult.map(d => d.day), data: dailySalesResult.map(d => parseFloat(d.sales)) };

        res.json({
            summary: { totalRevenue: parseFloat(summaryResult[0].totalRevenue || 0), totalOrders: summaryResult[0].totalOrders || 0 },
            dailySales: salesData,
            topProducts: topProductsResult || []
        });
    } catch (error) {
        console.error("Sales Summary Error:", error);
        res.status(500).json({ message: "Failed to fetch sales summary." });
    }
});

app.get('/api/reports/customer-comparison', verifyToken, hasPermission('view_reports'), async (req, res) => {
    const { customerId, monthA, monthB } = req.query;
    if (!customerId || !monthA || !monthB) {
        return res.status(400).json({ message: 'Customer ID, Month A, and Month B are required.' });
    }
    try {
        const query = `
            SELECT 
                SUM(CASE WHEN DATE_FORMAT(order_date, '%Y-%m') = ? THEN total_amount ELSE 0 END) as salesMonthA,
                SUM(CASE WHEN DATE_FORMAT(order_date, '%Y-%m') = ? THEN total_amount ELSE 0 END) as salesMonthB
            FROM orders
            WHERE customer_id = ? AND status != 'Cancelled' AND (DATE_FORMAT(order_date, '%Y-%m') = ? OR DATE_FORMAT(order_date, '%Y-%m') = ?)
        `;
        const [results] = await db.query(query, [monthA, monthB, customerId, monthA, monthB]);
        res.json({
            totalSalesMonthA: parseFloat(results[0].salesMonthA) || 0,
            totalSalesMonthB: parseFloat(results[0].salesMonthB) || 0,
        });
    } catch (error) {
        console.error("Error generating customer comparison report:", error);
        res.status(500).json({ message: 'Failed to generate report.' });
    }
});


// --- DATABASE INITIALIZATION SCRIPT ---
const initializeDatabase = async () => {
    try {
        console.log("Verifying and initializing database schema...");
        
        await db.query(`CREATE TABLE IF NOT EXISTS branches (id INT AUTO_INCREMENT PRIMARY KEY, name VARCHAR(100) NOT NULL UNIQUE, is_main_branch BOOLEAN DEFAULT FALSE) ENGINE=InnoDB;`);
        await db.query(`CREATE TABLE IF NOT EXISTS users (id INT AUTO_INCREMENT PRIMARY KEY, username VARCHAR(50) NOT NULL UNIQUE, password VARCHAR(255) NOT NULL, branch_id INT, is_active BOOLEAN DEFAULT TRUE, created_by INT NULL, max_agents INT DEFAULT 5, max_admins INT DEFAULT 1, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY (branch_id) REFERENCES branches(id) ON DELETE SET NULL, FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL) ENGINE=InnoDB;`);
        await db.query(`CREATE TABLE IF NOT EXISTS roles (id INT AUTO_INCREMENT PRIMARY KEY, name VARCHAR(50) NOT NULL UNIQUE) ENGINE=InnoDB;`);
        await db.query(`CREATE TABLE IF NOT EXISTS permissions (id INT AUTO_INCREMENT PRIMARY KEY, name VARCHAR(100) NOT NULL UNIQUE, description VARCHAR(255)) ENGINE=InnoDB;`);
        await db.query(`CREATE TABLE IF NOT EXISTS role_permissions (role_id INT NOT NULL, permission_id INT NOT NULL, PRIMARY KEY (role_id, permission_id), FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE, FOREIGN KEY (permission_id) REFERENCES permissions(id) ON DELETE CASCADE) ENGINE=InnoDB;`);
        await db.query(`CREATE TABLE IF NOT EXISTS user_roles (user_id INT NOT NULL, role_id INT NOT NULL, PRIMARY KEY (user_id, role_id), FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE, FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE) ENGINE=InnoDB;`);
        await db.query(`CREATE TABLE IF NOT EXISTS user_specific_permissions (user_id INT NOT NULL, permission_id INT NOT NULL, PRIMARY KEY (user_id, permission_id), FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE, FOREIGN KEY (permission_id) REFERENCES permissions(id) ON DELETE CASCADE) ENGINE=InnoDB;`);
        await db.query(`CREATE TABLE IF NOT EXISTS partners (id INT AUTO_INCREMENT PRIMARY KEY, name VARCHAR(100) NOT NULL UNIQUE) ENGINE=InnoDB;`);
        await db.query(`CREATE TABLE IF NOT EXISTS products (id INT AUTO_INCREMENT PRIMARY KEY, name VARCHAR(100) NOT NULL, description TEXT, price DECIMAL(10,2) NOT NULL, image_url VARCHAR(255), partner_id INT, category VARCHAR(255), unit VARCHAR(50) DEFAULT 'pcs', is_active BOOLEAN DEFAULT TRUE, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY (partner_id) REFERENCES partners(id) ON DELETE SET NULL) ENGINE=InnoDB;`);
        await db.query(`CREATE TABLE IF NOT EXISTS inventory (id INT AUTO_INCREMENT PRIMARY KEY, product_id INT NOT NULL UNIQUE, stock_quantity INT NOT NULL DEFAULT 0, FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE CASCADE) ENGINE=InnoDB;`);
        await db.query(`CREATE TABLE IF NOT EXISTS discounts (id INT AUTO_INCREMENT PRIMARY KEY, name VARCHAR(100) NOT NULL, type ENUM('PERCENTAGE', 'FIXED_AMOUNT', 'COD', 'BUY_GET') NOT NULL, value DECIMAL(10,2) DEFAULT 0, is_active BOOLEAN DEFAULT TRUE, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP) ENGINE=InnoDB;`);
        await db.query(`CREATE TABLE IF NOT EXISTS discount_product_assignments (discount_id INT NOT NULL, product_id INT NOT NULL, PRIMARY KEY (discount_id, product_id), FOREIGN KEY (discount_id) REFERENCES discounts(id) ON DELETE CASCADE, FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE CASCADE) ENGINE=InnoDB;`);
        await db.query(`CREATE TABLE IF NOT EXISTS customers (id INT AUTO_INCREMENT PRIMARY KEY, customer_code VARCHAR(100) NOT NULL UNIQUE, name VARCHAR(255) NOT NULL, address TEXT, agent_id INT, contact_number_1 VARCHAR(50), contact_number_2 VARCHAR(50), payment_terms INT DEFAULT 30, price_level_id INT, freight_duration INT DEFAULT 5, credit_limit DECIMAL(10,2) DEFAULT 0, branch_id INT NOT NULL, FOREIGN KEY (agent_id) REFERENCES users(id) ON DELETE SET NULL, FOREIGN KEY (price_level_id) REFERENCES discounts(id) ON DELETE SET NULL, FOREIGN KEY (branch_id) REFERENCES branches(id) ON DELETE RESTRICT) ENGINE=InnoDB;`);
        await db.query(`CREATE TABLE IF NOT EXISTS orders (id INT AUTO_INCREMENT PRIMARY KEY, agent_id INT NOT NULL, customer_id INT NOT NULL, total_amount DECIMAL(10,2) NOT NULL, discount DECIMAL(10,2) DEFAULT 0, source ENUM('pos', 'mobile') DEFAULT 'pos', status VARCHAR(50) DEFAULT 'Pending', payment_status ENUM('Paid', 'Unpaid', 'Refunded') DEFAULT 'Unpaid', invoice_no VARCHAR(255), order_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP, branch_id INT NOT NULL, FOREIGN KEY (agent_id) REFERENCES users(id) ON DELETE RESTRICT, FOREIGN KEY (customer_id) REFERENCES customers(id) ON DELETE RESTRICT, FOREIGN KEY (branch_id) REFERENCES branches(id) ON DELETE RESTRICT) ENGINE=InnoDB;`);
        await db.query(`CREATE TABLE IF NOT EXISTS order_items (id INT AUTO_INCREMENT PRIMARY KEY, order_id INT NOT NULL, product_id INT NOT NULL, quantity INT NOT NULL, price_per_unit DECIMAL(10,2) NOT NULL, discount_per_unit DECIMAL(10,2) DEFAULT 0, FOREIGN KEY (order_id) REFERENCES orders(id) ON DELETE CASCADE, FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE RESTRICT) ENGINE=InnoDB;`);
        
        const seedData = async (tableName, data, columns = ['id', 'name']) => {
            const [rows] = await db.query(`SELECT COUNT(*) as count FROM ${tableName}`);
            if (rows[0].count > 0) return;
            console.log(`Seeding ${tableName}...`);
            const query = `INSERT INTO ${tableName} (${columns.join(', ')}) VALUES ?`;
            const values = data.map(item => columns.map(col => item[col]));
            await db.query(query, [values]);
        };

        await seedData('roles', [{ id: 1, name: 'Super Admin' }, { id: 2, name: 'Admin' }, { id: 3, name: 'Agent' }, { id: 4, name: 'Sub-Admin' }]);
        await seedData('permissions', [
            { id: 101, name: 'view_dashboard' }, { id: 102, name: 'use_pos' }, { id: 103, name: 'manage_customers' },
            { id: 104, name: 'manage_products' }, { id: 105, name: 'manage_inventory' }, { id: 106, name: 'manage_orders' },
            { id: 107, name: 'manage_discounts' }, { id: 108, name: 'manage_accounting' }, { id: 109, name: 'view_reports' },
            { id: 201, name: 'manage_users' }, { id: 202, name: 'manage_branches' }
        ]);
        
        const [rolePermsCount] = await db.query(`SELECT COUNT(*) as count FROM role_permissions`);
        if (rolePermsCount[0].count === 0) {
            console.log('Seeding role_permissions...');
            const superAdminPerms = [ [1, 201], [1, 202] ];
            const adminPerms = [
                [2, 101], [2, 102], [2, 103], [2, 104], [2, 105], 
                [2, 106], [2, 107], [2, 108], [2, 109], [2, 201]
            ];
            const agentPerms = [[3, 102]];
            const allLinks = [...superAdminPerms, ...adminPerms, ...agentPerms];
            await db.query('INSERT INTO role_permissions (role_id, permission_id) VALUES ?', [allLinks]);
        }
        
        const [usersCount] = await db.query("SELECT COUNT(*) as count FROM users");
        if (usersCount[0].count === 0) {
            console.log('Creating default Super Admin user...');
            const hashedPassword = await bcrypt.hash('admin123', saltRounds);
            const [newUser] = await db.query("INSERT INTO users (username, password) VALUES (?, ?)", ['superadmin', hashedPassword]);
            const superAdminId = newUser.insertId;
            await db.query('INSERT INTO user_roles (user_id, role_id) VALUES (?, 1)', [superAdminId]);
        }

        console.log('Database schema verified and initialized successfully.');
    } catch (error) {
        console.error('FATAL: Database initialization failed:', error);
        process.exit(1);
    }
};

initializeDatabase().then(() => {
    app.listen(port, () => {
        console.log(`Bughaw Admin Server is live and running on http://localhost:${port}`);
    });
});