import express from "express";
import multer from "multer";
import cors from "cors";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import { v2 as cloudinary } from "cloudinary";
import dotenv from "dotenv";
import fs from "fs";
import nodemailer from "nodemailer";
import { neon } from "@neondatabase/serverless";
import axios from "axios";
import crypto from "crypto";

dotenv.config();

const app = express();
app.use((req, res, next) => {
  if (req.originalUrl === "/payments/webhook") {
    express.raw({ type: "application/json" })(req, res, next);
  } else {
    express.json()(req, res, next);
  }
});

app.use(express.urlencoded({ extended: true }));
app.use(cors());

const sql = neon(process.env.DATABASE_URL);

const PORT = process.env.PORT || 3000;

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

const upload = multer({ dest: "/tmp" });

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

const generateToken = (user) =>
  jwt.sign(
    {
      id: user.id,
      email: user.email,
      name: user.name,
      role: user.role,
    },
    process.env.JWT_SECRET,
    { expiresIn: "7d" }
  );

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  if (!authHeader) return res.status(401).json({ error: "Missing auth token" });
  const token = authHeader.split(" ")[1];
  if (!token) return res.status(401).json({ error: "Invalid auth token" });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: "Token invalid or expired" });
    req.user = user;
    next();
  });
};

const uploadImage = async (file) => {
  if (!file) return null;
  const result = await cloudinary.uploader.upload(file.path, {
    folder: "GIFTY CAKES",
  });
  fs.unlinkSync(file.path);
  return result.secure_url;
};

app.get("/", (req, res) => {
  res.send("Welcome to GIFTY CAKES API");
});

// User Management

//  REGISTER
app.post("/register", upload.single("image"), async (req, res) => {
  const { email, password, name, phoneNumber, role = "customer" } = req.body;
  if (!email || !password || !name)
    return res.status(400).json({ error: "All fields are required" });

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    let imageUrl = null;

    if (req.file) {
      imageUrl = await uploadImage(req.file);
    }

    // Check if user exists
    const existingUser = await sql`SELECT * FROM users WHERE email = ${email}`;
    if (existingUser.length > 0)
      return res.status(400).json({ error: "Email already registered" });

    // Insert user
    const insertedUser = await sql`
      INSERT INTO users (email, password, name, profile_image_url, phone_number, role)
      VALUES (${email}, ${hashedPassword}, ${name}, ${imageUrl}, ${phoneNumber}, ${role})
      RETURNING *
    `;
    const user = insertedUser[0];

    // Create cart for user
    await sql`INSERT INTO carts (user_id, grand_total) VALUES (${user.id}, 0)`;

    res.status(201).json({
      message: "User registered successfully",
      token: generateToken(user),
      user,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// LOGIN
app.post("/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const users = await sql`SELECT * FROM users WHERE email = ${email}`;
    const user = users[0];
    if (!user)
      return res.status(400).json({ error: "Invalid email or password" });

    const valid = await bcrypt.compare(password, user.password);
    if (!valid)
      return res.status(400).json({ error: "Invalid email or password" });

    const token = generateToken(user);
    res.json({ token, user });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET PROFILE
app.get("/auth/profile", authenticateToken, async (req, res) => {
  try {
    const users = await sql`SELECT * FROM users WHERE id = ${req.user.id}`;
    const user = users[0];
    if (!user) return res.status(404).json({ error: "User not found" });
    res.json(user);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// UPDATE PROFILE
app.put(
  "/auth/profile",
  authenticateToken,
  upload.single("image"),
  async (req, res) => {
    try {
      const { name, email, phoneNumber } = req.body;
      let updates = [];
      let values = [];
      let idx = 1;

      if (name) {
        updates.push(`name = $${idx++}`);
        values.push(name);
      }
      if (email) {
        updates.push(`email = $${idx++}`);
        values.push(email);
      }
      if (phoneNumber) {
        updates.push(`phone_number = $${idx++}`);
        values.push(phoneNumber);
      }

      let imageUrl;
      if (req.file) {
        imageUrl = await uploadImage(req.file);
        updates.push(`profile_image_url = $${idx++}`);
        values.push(imageUrl);
      }

      if (updates.length === 0)
        return res.status(400).json({ error: "No updates provided" });
      values.push(req.user.id);
      const updateQuery = `UPDATE users SET ${updates.join(
        ", "
      )} WHERE id = $${idx} RETURNING *`;
      const updated = await sql.unsafe(updateQuery, values);
      res.json(updated[0]);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  }
);

// --- Forgot Password ---
app.post("/auth/forgot-password", async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: "Email is required" });

  try {
    const users = await sql`SELECT * FROM users WHERE email = ${email}`;
    const user = users[0];
    if (!user) return res.status(404).json({ error: "User not found" });

    const resetToken = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, {
      expiresIn: "15m",
    });

    const resetUrl = `https://gifty-cakes.vercel.app/reset-password?token=${resetToken}`;

    await transporter.sendMail({
      from: `"GIFTY CAKES" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: "Password Reset Request",
      html: `<p>Click below to reset your password:</p><a href="${resetUrl}">${resetUrl}</a><p>Link expires in 15 minutes.</p>`,
    });

    res.json({ message: "Reset email sent if the account exists." });
  } catch (err) {
    console.error("Forgot password error:", err);
    res.status(500).json({ error: err.message });
  }
});

// --- Reset Password ---
app.post("/auth/reset-password", async (req, res) => {
  const { token, newPassword } = req.body;
  if (!token || !newPassword)
    return res.status(400).json({ error: "Token and new password required" });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const userId = decoded.userId;

    const users = await sql`SELECT * FROM users WHERE id = ${userId}`;
    const user = users[0];
    if (!user)
      return res.status(400).json({ error: "Invalid token or user not found" });

    const hashedPassword = await bcrypt.hash(newPassword, 10);

    await sql`UPDATE users SET password = ${hashedPassword} WHERE id = ${userId}`;

    res.json({ message: "Password has been reset successfully" });
  } catch (err) {
    console.error("Reset password error:", err);
    res.status(400).json({ error: "Invalid or expired token" });
  }
});

// PRODUCTS ENDPOINTS

// GET ALL PRODUCTS
app.get("/products", async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const offset = (page - 1) * limit;
    const search = req.query.search ? req.query.search.trim() : "";

    let products, totalArr, total;
    if (search) {
      products = await sql`
        SELECT * FROM products
        WHERE name ILIKE ${"%" + search + "%"} OR description ILIKE ${
        "%" + search + "%"
      }
        ORDER BY id DESC
        LIMIT ${limit} OFFSET ${offset}
      `;
      totalArr = await sql`
        SELECT COUNT(*)::int AS count FROM products
        WHERE name ILIKE ${"%" + search + "%"} OR description ILIKE ${
        "%" + search + "%"
      }
      `;
    } else {
      products = await sql`
        SELECT * FROM products
        ORDER BY id DESC
        LIMIT ${limit} OFFSET ${offset}
      `;
      totalArr = await sql`SELECT COUNT(*)::int FROM products`;
    }
    total = totalArr[0]?.count || 0;

    res.json({
      products,
      page,
      limit,
      total,
      totalPages: Math.ceil(total / limit),
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET PRODUCT BY ID
app.get("/products/:id", async (req, res) => {
  const { id } = req.params;
  try {
    const products = await sql`SELECT * FROM products WHERE id = ${id}`;
    const product = products[0];
    if (!product) return res.status(404).json({ error: "Product not found" });
    res.json(product);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// CREATE CUSTOM CAKE ORDER (add to cart)
app.post("/product/cake", authenticateToken, async (req, res) => {
  const { size, flavor, quantity = 1, message = "", price } = req.body;
  if (!size || !flavor || !quantity || !price) {
    return res
      .status(400)
      .json({ error: "Size, flavor, quantity, and price are required" });
  }

  try {
    const cart = await getOrCreateCart(req.user.id);
    // Insert as a cart item with a description and message
    const inserted = await sql`
      INSERT INTO cart_items (cart_id, product_id, quantity, price, custom_description, custom_message)
      VALUES (${cart.id}, NULL, ${quantity}, ${price}, ${
      size + " " + flavor + " cake"
    }, ${message})
      RETURNING *
    `;
    const cartItem = inserted[0];
    const grand_total = await updateGrandTotal(req.user.id);
    res.status(201).json({ ...cartItem, grand_total });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PAYMENT MANAGEMENT

// INITIATE CHECKOUT (Paystack compatible)
app.post("/checkout/initiate", authenticateToken, async (req, res) => {
  const { delivery_fee = 0, payment_method } = req.body;
  try {
    const cart = await getOrCreateCart(req.user.id);
    const items =
      await sql`SELECT * FROM cart_items WHERE cart_id = ${cart.id}`;
    if (!items.length) {
      return res.status(400).json({ error: "Cart is empty" });
    }
    const subtotal = items.reduce((sum, i) => sum + Number(i.price), 0);
    const total = subtotal + Number(delivery_fee);
    res.json({
      cart_items: items,
      subtotal,
      delivery_fee,
      total,
      payment_method,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// CONFIRM CHECKOUT (Paystack compatible)
app.post("/checkout/confirm", authenticateToken, async (req, res) => {
  const {
    email,
    first_name,
    last_name,
    phone,
    address,
    city,
    delivery_date,
    delivery_time,
    delivery_fee = 0,
    payment_method,
  } = req.body;

  if (payment_method === "pay on delivery") {
    try {
      const cart = await getOrCreateCart(req.user.id);
      const items =
        await sql`SELECT * FROM cart_items WHERE cart_id = ${cart.id}`;
      if (!items.length) {
        return res.status(400).json({ error: "Cart is empty" });
      }
      const subtotal = items.reduce((sum, i) => sum + Number(i.price), 0);
      const total = subtotal + Number(delivery_fee);

      const insertedOrder = await sql`
        INSERT INTO orders (user_id, total, delivery_fee, delivery_date, delivery_time, payment_method, status)
        VALUES (${req.user.id}, ${total}, ${delivery_fee}, ${delivery_date}, ${delivery_time}, ${payment_method}, 'pending')
        RETURNING *
      `;
      const order = insertedOrder[0];

      await sql`
        INSERT INTO shipping_addresses (user_id, order_id, email, first_name, last_name, phone, address, city, delivery_date, delivery_time)
        VALUES (${req.user.id}, ${order.id}, ${email}, ${first_name}, ${last_name}, ${phone}, ${address}, ${city}, ${delivery_date}, ${delivery_time})
      `;

      for (const item of items) {
        await sql`
          INSERT INTO order_items (order_id, product_id, quantity, price)
          VALUES (${order.id}, ${item.product_id}, ${item.quantity}, ${item.price})
        `;
      }

      await sql`DELETE FROM cart_items WHERE cart_id = ${cart.id}`;
      await sql`UPDATE carts SET grand_total = 0 WHERE id = ${cart.id}`;

      const shippingArr =
        await sql`SELECT * FROM shipping_addresses WHERE order_id = ${order.id}`;
      const shipping = shippingArr[0];
      const orderItems = await sql`
        SELECT *, (SELECT row_to_json(p) FROM products p WHERE p.id = order_items.product_id) as product
        FROM order_items WHERE order_id = ${order.id}
      `;

      res.status(201).json({
        message: "Order placed successfully",
        order: {
          ...order,
          shipping,
          items: orderItems,
        },
      });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  } else {
    res.status(400).json({ error: "Unsupported payment method" });
  }
});

// ORDER MANAGEMENT

app.get("/orders", authenticateToken, async (req, res) => {
  try {
    const { filter, page = 1, limit = 20 } = req.query;
    const offset = (parseInt(page) - 1) * parseInt(limit);

    const userId = parseInt(req.user.user_id || req.user.id, 10);
    if (!userId) {
      return res.status(401).json({ error: "User not found in token" });
    }

    // Count total
    let totalArr;
    if (filter && ["pending", "paid", "completed"].includes(filter)) {
      totalArr = await sql`
        SELECT COUNT(*)::int AS count
        FROM orders
        WHERE user_id = ${userId} AND status = ${filter}
      `;
    } else {
      totalArr = await sql`
        SELECT COUNT(*)::int AS count
        FROM orders
        WHERE user_id = ${userId}
      `;
    }
    const total = totalArr[0]?.count || 0;

    // Get paginated orders
    let ordersResult;
    if (filter && ["pending", "paid", "completed"].includes(filter)) {
      ordersResult = await sql`
        SELECT *
        FROM orders
        WHERE user_id = ${userId} AND status = ${filter}
        ORDER BY created_at DESC
        LIMIT ${limit} OFFSET ${offset}
      `;
    } else {
      ordersResult = await sql`
        SELECT *
        FROM orders
        WHERE user_id = ${userId}
        ORDER BY created_at DESC
        LIMIT ${limit} OFFSET ${offset}
      `;
    }

    const orders = ordersResult || [];

    // Enrich with shipping + items
    const enrichedOrders = await Promise.all(
      (orders || []).map(async (order) => {
        const shipping = (
          await sql`
        SELECT * FROM shipping_addresses WHERE order_id = ${order.id}
      `
        )[0];
        const items = await sql`
        SELECT *, (
          SELECT row_to_json(p)
          FROM products p
          WHERE p.id = order_items.product_id
        ) as product
        FROM order_items
        WHERE order_id = ${order.id}
      `;
        return { ...order, shipping, items };
      })
    );

    res.json({
      orders: enrichedOrders,
      page: parseInt(page),
      limit: parseInt(limit),
      total,
      totalPages: Math.ceil(total / limit),
    });
  } catch (err) {
    console.error("Error fetching orders:", err);
    res.status(500).json({ error: err.message });
  }
});

// GET ORDER BY ID
app.get("/orders/:id", authenticateToken, async (req, res) => {
  const { id } = req.params;
  try {
    const orders =
      await sql`SELECT * FROM orders WHERE id = ${id} AND user_id = ${req.user.id}`;
    const order = orders[0];
    if (!order) return res.status(404).json({ error: "Order not found" });
    const shippingArr =
      await sql`SELECT * FROM shipping_addresses WHERE order_id = ${order.id}`;
    const shipping = shippingArr[0];
    const items =
      await sql`SELECT *, (SELECT row_to_json(p) FROM products p WHERE p.id = order_items.product_id) as product FROM order_items WHERE order_id = ${order.id}`;
    res.json({ ...order, shipping, items });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ADMIN FUNCTIONS

// GET ALL USER
app.get("/users", authenticateToken, async (req, res) => {
  if (req.user.role !== "admin")
    return res.status(403).json({ error: "Only admins can view users" });

  try {
    const users = await sql`SELECT * FROM users`;
    res.json(users);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// --- GET ALL ORDERS (ADMIN) ---
app.get("/admin/orders", authenticateToken, async (req, res) => {
  if (req.user.role !== "admin") {
    return res.status(403).json({ error: "Only admins can view orders" });
  }

  try {
    const { filter, page = 1, limit = 20 } = req.query;
    const pageNum = parseInt(page);
    const limitNum = parseInt(limit);
    const offset = (pageNum - 1) * limitNum;

    // Build dynamic query
    let whereClause = "";
    const params = [];

    if (filter && ["pending", "paid", "completed"].includes(filter)) {
      whereClause = `WHERE o.status = $1`;
      params.push(filter);
    }

    // Count
    const countQuery = `
      SELECT COUNT(*)::int AS count
      FROM orders o
      ${whereClause}
    `;
    const countResult = await sql.query(countQuery, params);
    const total = countResult[0]?.count || 0;

    // Orders with JOINs
    const ordersQuery = `
      SELECT 
        o.*,
        json_build_object(
          'email', s.email,
          'first_name', s.first_name,
          'last_name', s.last_name,
          'phone', s.phone,
          'address', s.address,
          'city', s.city,
          'delivery_date', s.delivery_date,
          'delivery_time', s.delivery_time
        ) AS shipping
      FROM orders o
      LEFT JOIN shipping_addresses s ON o.id = s.order_id
      ${whereClause}
      ORDER BY o.created_at DESC
      LIMIT $${params.length + 1} OFFSET $${params.length + 2}
    `;
    const orderResults = await sql.query(ordersQuery, [
      ...params,
      limitNum,
      offset,
    ]);

    // Attach order items
    const enrichedOrders = await Promise.all(
      orderResults.map(async (order) => {
        const itemsRes = await sql`
          SELECT oi.*, (
            SELECT row_to_json(p)
            FROM products p
            WHERE p.id = oi.product_id
          ) AS product
          FROM order_items oi
          WHERE oi.order_id = ${order.id}
        `;
        return {
          ...order,
          items: itemsRes,
        };
      })
    );

    res.json({
      orders: enrichedOrders,
      page: pageNum,
      limit: limitNum,
      total,
      totalPages: Math.ceil(total / limitNum),
    });
  } catch (err) {
    console.error("Admin order fetch error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});



// GET ALL PRODUCTS (Admin)
app.get("/admin/products", authenticateToken, async (req, res) => {
  if (req.user.role !== "admin")
    return res.status(403).json({ error: "Only admins can view products" });

  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const offset = (page - 1) * limit;

    const products = await sql`
      SELECT * FROM products
      ORDER BY id DESC
      LIMIT ${limit} OFFSET ${offset}
    `;
    const totalArr = await sql`SELECT COUNT(*)::int FROM products`;
    const total = totalArr[0]?.count || 0;

    res.json({
      products,
      page,
      limit,
      total,
      totalPages: Math.ceil(total / limit),
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// EDIT ORDER STATUS (Admin)
app.put("/admin/orders/:id/status", authenticateToken, async (req, res) => {
  if (req.user.role !== "admin")
    return res.status(403).json({ error: "Only admins can edit orders" });

  const { id } = req.params;
  const { status } = req.body;
  if (!status) return res.status(400).json({ error: "Status is required" });

  try {
    const updated =
      await sql`UPDATE orders SET status = ${status} WHERE id = ${id} RETURNING *`;
    if (!updated[0]) return res.status(404).json({ error: "Order not found" });
    res.json(updated[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ADD PRODUCT (Admin)
app.post(
  "/admin/products",
  authenticateToken,
  upload.single("image"),
  async (req, res) => {
    if (req.user.role !== "admin") {
      return res.status(403).json({ error: "Only admins can add products" });
    }
    try {
      const { name, description, amount } = req.body;
      if (!name || !description || !amount) {
        return res
          .status(400)
          .json({ error: "Name, description, and amount are required" });
      }
      let image_url = null;
      if (req.file) {
        image_url = await uploadImage(req.file);
      }
      const inserted = await sql`
      INSERT INTO products (name, description, amount, image_url)
      VALUES (${name}, ${description}, ${amount}, ${image_url})
      RETURNING *
    `;
      res.status(201).json(inserted[0]);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  }
);

// EDIT PRODUCT (Admin)
app.put(
  "/admin/products/:id",
  authenticateToken,
  upload.single("image"),
  async (req, res) => {
    if (req.user.role !== "admin") {
      return res.status(403).json({ error: "Only admins can update products" });
    }

    const { id } = req.params;
    const productId = parseInt(id, 10);
    if (isNaN(productId)) {
      return res.status(400).json({ error: "Invalid product id" });
    }

    try {
      let { name, description, amount } = req.body;
      let image_url;

      if (req.file) {
        image_url = await uploadImage(req.file); // your Cloudinary upload function
      }

      const updates = {};

      if (name !== undefined) {
        if (typeof name !== "string" || !name.trim()) {
          return res
            .status(400)
            .json({ error: "Name must be a non-empty string" });
        }
        updates.name = name.trim();
      }

      if (description !== undefined) {
        if (typeof description !== "string" || !description.trim()) {
          return res
            .status(400)
            .json({ error: "Description must be a non-empty string" });
        }
        updates.description = description.trim();
      }

      if (amount !== undefined) {
        const amt = Number(amount);
        if (isNaN(amt)) {
          return res
            .status(400)
            .json({ error: "Amount must be a valid number" });
        }
        updates.amount = amt;
      }

      if (image_url !== undefined) {
        updates.image_url = image_url;
      }

      if (Object.keys(updates).length === 0) {
        return res.status(400).json({ error: "No updates provided" });
      }

      // Check if product exists
      const existing =
        await sql`SELECT id FROM products WHERE id = ${productId}`;
      if (!existing.length) {
        return res.status(404).json({ error: "Product not found" });
      }

      // Build the dynamic SQL query using `sql.query`
      const keys = Object.keys(updates);
      const values = Object.values(updates);
      values.push(productId); // Adding productId for the WHERE clause

      // Build SET clause with placeholders ($1, $2, etc.)
      const setClause = keys.map((key, i) => `${key} = $${i + 1}`).join(", ");
      const updateQuery = `
      UPDATE products
      SET ${setClause}
      WHERE id = $${keys.length + 1}
      RETURNING id, name, description, amount, image_url
    `;

      // Execute the update query
      const result = await sql.query(updateQuery, values);

      // Return the updated product details
      res.json(result[0]);
    } catch (err) {
      console.error("Product update error:", err);
      res.status(500).json({ error: "Internal server error" });
    }
  }
);

// DELETE PRODUCT (Admin)
app.delete("/admin/products/:id", authenticateToken, async (req, res) => {
  if (req.user.role !== "admin") {
    return res.status(403).json({ error: "Only admins can delete products" });
  }
  const { id } = req.params;
  try {
    // Remove related cart_items and order_items
    await sql`DELETE FROM cart_items WHERE product_id = ${id}`;
    await sql`DELETE FROM order_items WHERE product_id = ${id}`;
    const deleted =
      await sql`DELETE FROM products WHERE id = ${id} RETURNING *`;
    if (!deleted[0])
      return res.status(404).json({ error: "Product not found" });
    res.json({ message: "Product deleted successfully" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// CART MANAGEMENT

// Helper: Get or create cart
async function getOrCreateCart(userId) {
  const carts = await sql`SELECT * FROM carts WHERE user_id = ${userId}`;
  if (carts.length > 0) return carts[0];
  const inserted =
    await sql`INSERT INTO carts (user_id, grand_total) VALUES (${userId}, 0) RETURNING *`;
  return inserted[0];
}

// Helper: Update grand total
async function updateGrandTotal(userId) {
  try {
    const cart = await getOrCreateCart(userId);
    const items =
      await sql`SELECT price, quantity FROM cart_items WHERE cart_id = ${cart.id}`;
    const grandTotal = items.reduce((sum, item) => sum + Number(item.price), 0);
    await sql`UPDATE carts SET grand_total = ${grandTotal} WHERE id = ${cart.id}`;
    return grandTotal;
  } catch (err) {
    console.error("Grand total update failed:", err.message);
    return 0;
  }
}

// ADD TO CART
app.post("/cart", authenticateToken, async (req, res) => {
  const { productId, quantity } = req.body;
  if (!productId || !quantity) {
    return res.status(400).json({ error: "Product and quantity required" });
  }
  try {
    const cart = await getOrCreateCart(req.user.id);
    const products = await sql`SELECT * FROM products WHERE id = ${productId}`;
    const product = products[0];
    if (!product) return res.status(404).json({ error: "Product not found" });
    const finalPrice = Number(product.amount) * quantity;
    const inserted = await sql`
      INSERT INTO cart_items (cart_id, product_id, quantity, price)
      VALUES (${cart.id}, ${productId}, ${quantity}, ${finalPrice})
      RETURNING *
    `;
    const cartItem = inserted[0];
    const grand_total = await updateGrandTotal(req.user.id);
    res.status(201).json({ ...cartItem, grand_total });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET CART
app.get("/cart", authenticateToken, async (req, res) => {
  try {
    const cart = await getOrCreateCart(req.user.id);
    const items =
      await sql`SELECT * FROM cart_items WHERE cart_id = ${cart.id}`;
    const enriched = await Promise.all(
      items.map(async (item) => {
        const products =
          await sql`SELECT * FROM products WHERE id = ${item.product_id}`;
        return {
          ...item,
          product: products[0] || {},
          total_price: item.price,
        };
      })
    );
    const grand_total = enriched.reduce(
      (sum, i) => sum + Number(i.total_price),
      0
    );
    res.json({ items: enriched, grand_total });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// UPDATE CART ITEM
app.put("/cart/:id", authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { quantity } = req.body;
  if (!quantity) return res.status(400).json({ error: "Quantity is required" });
  try {
    const cart = await getOrCreateCart(req.user.id);
    const items =
      await sql`SELECT * FROM cart_items WHERE id = ${id} AND cart_id = ${cart.id}`;
    const item = items[0];
    if (!item) return res.status(404).json({ error: "Cart item not found" });
    const unit_price = Number(item.price) / item.quantity;
    const new_price = unit_price * quantity;
    const updated =
      await sql`UPDATE cart_items SET quantity = ${quantity}, price = ${new_price} WHERE id = ${id} RETURNING *`;
    const grand_total = await updateGrandTotal(req.user.id);
    res.json({ ...updated[0], grand_total });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// DELETE CART ITEM
app.delete("/cart/:id", authenticateToken, async (req, res) => {
  const { id } = req.params;
  try {
    const cart = await getOrCreateCart(req.user.id);
    const deleted =
      await sql`DELETE FROM cart_items WHERE id = ${id} AND cart_id = ${cart.id} RETURNING *`;
    if (!deleted[0])
      return res.status(404).json({ error: "Cart item not found" });
    const grand_total = await updateGrandTotal(req.user.id);
    res.json({ message: "Deleted", grand_total });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PAYMENT MANAGEMENT
// PAYMENT INITIATION (Paystack)
app.post("/payments/initiate", authenticateToken, async (req, res) => {
  const {
    email,
    delivery_date,
    delivery_time,
    first_name,
    last_name,
    phone,
    address,
    city,
  } = req.body;

  try {
    if (!process.env.PAYSTACK_SECRET) {
      return res
        .status(500)
        .json({ error: "PAYSTACK_SECRET is not set in environment variables" });
    }

    // get user cart
    const cart = await getOrCreateCart(req.user.id);
    const items =
      await sql`SELECT * FROM cart_items WHERE cart_id = ${cart.id}`;
    if (!items.length) return res.status(400).json({ error: "Cart is empty" });

    // ✅ FIX subtotal: price * quantity
    const subtotal = items.reduce(
      (sum, i) => sum + Number(i.price) * i.quantity,
      0
    );
    const delivery_fee = 1000; // flat fee
    const total = subtotal + delivery_fee;

    // initialize Paystack transaction
    const response = await axios.post(
      "https://api.paystack.co/transaction/initialize",
      {
        email,
        amount: total * 100, // kobo
        currency: "NGN",
        callback_url: `${process.env.FRONTEND_URL}/orders`,
        metadata: {
          user_id: req.user.id,
          delivery_fee,
          delivery_date,
          delivery_time,
          address,
          phone,
          first_name,
          last_name,
          city,
          cart: items,
        },
      },
      {
        headers: {
          Authorization: `Bearer ${process.env.PAYSTACK_SECRET}`,
          "Content-Type": "application/json",
        },
      }
    );

    res.json(response.data.data);
  } catch (err) {
    console.error(
      "Paystack initiation error:",
      err.response?.data || err.message
    );
    res.status(500).json({
      error: "Failed to initiate Paystack payment",
      details: err.response?.data || err.message,
    });
  }
});

// ✅ PAYSTACK WEBHOOK
app.post(
  "/payments/webhook",
  express.raw({ type: "application/json" }),
  async (req, res) => {
    try {
      const signature = req.headers["x-paystack-signature"];
      if (!signature) return res.status(400).send("Missing signature");

      const rawBody = req.body;
      const hash = crypto
        .createHmac("sha512", process.env.PAYSTACK_SECRET)
        .update(rawBody)
        .digest("hex");

      if (hash !== signature) {
        console.error("❌ Invalid Paystack signature");
        return res.status(401).send("Invalid signature");
      }

      const event = JSON.parse(rawBody.toString());
      const { event: eventType, data } = event;
      console.log("✅ Verified webhook:", eventType);

      if (eventType === "charge.success" && data.status === "success") {
        const ref = data.reference;
        const metadata = data.metadata || {};
        const user_id = metadata.user_id;

        // avoid duplicate order
        const existing =
          await sql`SELECT * FROM orders WHERE payment_intent_id = ${ref}`;
        if (existing.length) {
          console.log("⚠️ Order already exists for reference:", ref);
          return res.sendStatus(200);
        }

        // get user cart
        const cart = await getOrCreateCart(user_id);
        const cartItems =
          await sql`SELECT * FROM cart_items WHERE cart_id = ${cart.id}`;

        // subtotal and delivery
        const subtotal = cartItems.reduce(
          (sum, i) => sum + Number(i.price) * i.quantity,
          0
        );
        const delivery_fee = metadata.delivery_fee || 0;
        const total = (data.amount || subtotal + delivery_fee) / 100;

        // ✅ insert order
        const [order] = await sql`
          INSERT INTO orders (
            user_id,
            total,
            delivery_fee,
            delivery_date,
            delivery_time,
            payment_method,
            payment_intent_id,
            status
          )
          VALUES (
            ${user_id},
            ${total},
            ${delivery_fee},
            ${metadata.delivery_date},
            ${metadata.delivery_time},
            'paystack',
            ${ref},
            'paid'
          )
          RETURNING id
        `;

        // ✅ insert shipping info
        await sql`
          INSERT INTO shipping_addresses (
            user_id,
            order_id,
            email,
            first_name,
            last_name,
            phone,
            address,
            city,
            delivery_date,
            delivery_time
          ) VALUES (
            ${metadata.user_id},
            ${order.id},
            ${metadata.email},
            ${metadata.first_name},
            ${metadata.last_name},
            ${metadata.phone},
            ${metadata.address},
            ${metadata.city},
            ${metadata.delivery_date},
            ${metadata.delivery_time}
          )
        `;

        // ✅ insert order items
        for (const item of cartItems) {
          await sql`
            INSERT INTO order_items (
              order_id,
              product_id,
              quantity,
              price,
              custom_description,
              custom_message
            )
            VALUES (
              ${order.id},
              ${item.product_id || null},
              ${item.quantity},
              ${item.price * item.quantity},
              ${item.custom_description || null},
              ${item.custom_message || null}
            )
          `;
        }

        // ✅ clear cart
        await sql`DELETE FROM cart_items WHERE cart_id = ${cart.id}`;

        console.log(
          `🎉 Order ${order.id} created for user ${user_id} with total ₦${total}`
        );
      }

      res.sendStatus(200);
    } catch (err) {
      console.error("❌ Webhook error:", err.message);
      res.sendStatus(500);
    }
  }
);


app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
