require("dotenv").config();
const express = require("express");
const mysql = require("mysql2");
const bcrypt = require("bcryptjs");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const multerS3 = require("multer-s3");
const { S3Client, DeleteObjectCommand } = require("@aws-sdk/client-s3");
const axios = require("axios"); // <-- เพิ่มบรรทัดนี้เข้ามา

const app = express();
app.use(cors());
app.use(express.json());

// --- NEW: R2/S3 Client and Multer S3 Setup ---
const s3 = new S3Client({
  region: "auto",
  endpoint: `https://${process.env.CLOUDFLARE_ACCOUNT_ID}.r2.cloudflarestorage.com`,
  credentials: {
    accessKeyId: process.env.CLOUDFLARE_ACCESS_KEY_ID,
    secretAccessKey: process.env.CLOUDFLARE_SECRET_ACCESS_KEY,
  },
});

// สร้างตัวอัปโหลดเพียงตัวเดียวที่ใช้ได้กับทุกส่วน
const uploadR2 = multer({
  storage: multerS3({
    s3: s3,
    bucket: process.env.R2_BUCKET_NAME,
    acl: "public-read",
    metadata: function (req, file, cb) {
      cb(null, { fieldName: file.fieldname });
    },
    key: function (req, file, cb) {
      let folder = "others/";
      if (req.path.includes("/products")) folder = "products/";
      if (req.path.includes("/store-info")) folder = "store/";
      if (req.path.includes("/receipt")) folder = "receipts/";
      const fileName = `${folder}${Date.now()}-${file.originalname}`;
      cb(null, fileName);
    },
  }),
});

const deleteFileFromR2 = async (fileUrl) => {
  if (!fileUrl) return; // ถ้าไม่มี URL ก็ไม่ต้องทำอะไร

  try {
    // ดึง Key (path + filename) ออกมาจาก URL เต็ม
    // เช่น https://<...>.r2.dev/products/123.jpg -> products/123.jpg
    const fileKey = new URL(fileUrl).pathname.substring(1);

    const deleteParams = {
      Bucket: process.env.R2_BUCKET_NAME,
      Key: fileKey,
    };

    // ส่งคำสั่งลบไปที่ R2
    await s3.send(new DeleteObjectCommand(deleteParams));
    console.log(`Successfully deleted ${fileKey} from R2.`);
  } catch (error) {
    console.error("Error deleting file from R2:", error);
  }
};

// const db = mysql
//   .createPool({
//     host: process.env.DB_HOST,
//     user: process.env.DB_USER,
//     password: process.env.DB_PASSWORD,
//     database: process.env.DB_DATABASE,
//     waitForConnections: true,
//     connectionLimit: 10,
//     queueLimit: 0,
//   })
//   .promise();

const db = mysql
  .createPool({
    host: process.env.TIDB_HOST,
    port: process.env.TIDB_PORT,
    user: process.env.TIDB_USER,
    password: process.env.TIDB_PASSWORD,
    database: process.env.TIDB_DATABASE,

    ssl: process.env.TIDB_SSL_CERT
      ? { ca: fs.readFileSync(process.env.TIDB_SSL_CERT) }
      : null,

    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
  })
  .promise();

// --- API Endpoint สำหรับการลงทะเบียน ---
app.post("/api/register", async (req, res) => {
  const { username, email, password, phone, address } = req.body;
  if (!username || !email || !password) {
    return res
      .status(400)
      .json({ message: "กรุณากรอกชื่อผู้ใช้, อีเมล และรหัสผ่าน" });
  }
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const sql =
      "INSERT INTO Users (username, email, password, role_id, phone, address) VALUES (?, ?, ?, ?, ?, ?)";
    await db.query(sql, [
      username,
      email,
      hashedPassword,
      1,
      phone || null,
      address || null,
    ]);
    res.status(201).json({ message: "ลงทะเบียนสำเร็จ!" });
  } catch (error) {
    if (error.code === "ER_DUP_ENTRY") {
      return res
        .status(409)
        .json({ message: "ชื่อผู้ใช้หรืออีเมลนี้มีอยู่ในระบบแล้ว" });
    }
    console.error("Server Error:", error);
    res.status(500).json({ message: "เกิดข้อผิดพลาดในการลงทะเบียน" });
  }
});

// --- API Endpoint สำหรับการล็อกอิน ---
app.post("/api/login", async (req, res) => {
  const { identifier, password } = req.body;

  if (!identifier || !password) {
    return res
      .status(400)
      .json({ message: "กรุณากรอกชื่อผู้ใช้/อีเมล และรหัสผ่าน" });
  }

  try {
    const sql = `
      SELECT u.*, r.role_name 
      FROM Users u 
      JOIN Role r ON u.role_id = r.role_id 
      WHERE u.username = ? OR u.email = ?
    `;
    const [users] = await db.query(sql, [identifier, identifier]);

    if (users.length === 0) {
      return res
        .status(401)
        .json({ message: "ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง" });
    }

    const user = users[0];
    const isPasswordMatch = await bcrypt.compare(password, user.password);

    if (!isPasswordMatch) {
      return res
        .status(401)
        .json({ message: "ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง" });
    }

    // สร้าง JWT Token
    const payload = {
      userId: user.user_id,
      username: user.username,
      role: user.role_name,
    };

    const token = jwt.sign(payload, process.env.JWT_SECRET, {
      expiresIn: "1h", // Token มีอายุ 1 ชั่วโมง
    });

    const userInfo = {
      userId: user.user_id,
      username: user.username,
      email: user.email,
      role: user.role_name,
      points: user.points,
    };

    // ส่ง Token กลับไปพร้อมกับข้อมูลผู้ใช้
    res.status(200).json({
      message: "ล็อกอินสำเร็จ!",
      token: token,
      user: userInfo,
    });
  } catch (error) {
    console.error("Database Error:", error);
    return res.status(500).json({ message: "เกิดข้อผิดพลาดในเซิร์ฟเวอร์" });
  }
});

// สร้าง Middleware สำหรับตรวจสอบ Token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (token == null) return res.sendStatus(401);

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// --- API สำหรับฝั่งลูกค้า---

// API Endpoint สำหรับดึงข้อมูลสินค้าทั้งหมด
app.get("/api/products", async (req, res) => {
  try {
    const { category, recommended } = req.query;

    let sql = "SELECT * FROM Product WHERE sales_status = 1";
    const params = [];

    if (category) {
      sql += " AND category_id = ?";
      params.push(category);
    }

    if (recommended === "true") {
      sql += " AND recommend_status = 1";
    }

    sql += " ORDER BY product_id DESC";

    const [products] = await db.query(sql, params);
    res.status(200).json(products);
  } catch (error) {
    console.error("Database Error:", error);
    res.status(500).json({ message: "เกิดข้อผิดพลาดในการดึงข้อมูลสินค้า" });
  }
});

// GET: API สำหรับดึง Categories (แบบ Public - เวอร์ชันอัปเดต)
app.get("/api/public/categories", async (req, res) => {
  try {
    const sql = `
            SELECT category_id, category_name, category_name_en FROM Category 
            WHERE category_id IN (
                SELECT DISTINCT category_id FROM Product WHERE sales_status = 1
            )
            ORDER BY category_id
        `;
    const [categories] = await db.query(sql);
    res.json(categories);
  } catch (error) {
    res.status(500).json({ message: "Error fetching categories" });
  }
});

// API ดึงข้อมูลสินค้าชิ้นเดียวตาม ID
app.get("/api/product/:id", async (req, res) => {
  const { id } = req.params; // ดึง id มาจาก URL parameter

  try {
    const sql = "SELECT * FROM Product WHERE product_id = ?";
    const [products] = await db.query(sql, [id]);

    if (products.length === 0) {
      return res.status(404).json({ message: "ไม่พบสินค้าชิ้นนี้" });
    }

    res.status(200).json(products[0]); // ส่งข้อมูลสินค้าตัวแรกที่เจอ
  } catch (error) {
    console.error("Get Single Product Error:", error);
    res.status(500).json({ message: "เกิดข้อผิดพลาดในการดึงข้อมูลสินค้า" });
  }
});

// API สำหรับเพิ่มสินค้าลงตะกร้า (Protected Route)
app.post("/api/cart/add", authenticateToken, async (req, res) => {
  //  ดึงข้อมูลจาก request body และ token
  const { productId, quantity } = req.body;
  const userId = req.user.userId;

  if (!productId || !quantity) {
    return res.status(400).json({ message: "ข้อมูลไม่ครบถ้วน" });
  }

  try {
    const connection = await db.getConnection();

    // ตรวจสอบว่ามีสินค้านี้ในตะกร้าของผู้ใช้อยู่แล้วหรือไม่
    const checkSql =
      "SELECT * FROM CartItem WHERE user_id = ? AND product_id = ?"; //
    const [existingItems] = await connection.query(checkSql, [
      userId,
      productId,
    ]);

    if (existingItems.length > 0) {
      // ถ้ามีอยู่แล้ว ให้อัปเดตจำนวนสินค้า
      const newQuantity = existingItems[0].quantity + quantity;
      const updateSql =
        "UPDATE CartItem SET quantity = ? WHERE cart_item_id = ?"; //
      await connection.query(updateSql, [
        newQuantity,
        existingItems[0].cart_item_id,
      ]);
      res
        .status(200)
        .json({ message: `อัปเดตจำนวนสินค้าในตะกร้าเรียบร้อยแล้ว` });
    } else {
      // ถ้ายังไม่มี ให้เพิ่มเป็นรายการใหม่ในตะกร้า
      const insertSql =
        "INSERT INTO CartItem (user_id, product_id, quantity) VALUES (?, ?, ?)"; //
      await connection.query(insertSql, [userId, productId, quantity]);
      res.status(201).json({ message: `เพิ่มสินค้าลงตะกร้าสำเร็จ!` });
    }

    connection.release();
  } catch (error) {
    // Error
    console.error("Cart Add Error:", error);
    res.status(500).json({ message: "เกิดข้อผิดพลาดในการเพิ่มสินค้าลงตะกร้า" });
  }
});

// API ดึงข้อมูลสินค้าทั้งหมดในตะกร้าของผู้ใช้
app.get("/api/cart", authenticateToken, async (req, res) => {
  const userId = req.user.userId;

  try {
    const sql = `
      SELECT 
          ci.cart_item_id, 
          ci.quantity, 
          p.product_id,
          p.name,
          p.name_en,
          p.price,
          p.image_url,
          p.sales_status
      FROM CartItem ci
      JOIN Product p ON ci.product_id = p.product_id
      WHERE ci.user_id = ?
      ORDER BY ci.cart_item_id DESC
    `;
    const [items] = await db.query(sql, [userId]);
    res.status(200).json(items);
  } catch (error) {
    console.error("Get Cart Error:", error);
    res
      .status(500)
      .json({ message: "เกิดข้อผิดพลาดในการดึงข้อมูลตะกร้าสินค้า" });
  }
});

//  อัปเดตจำนวนสินค้าในตะกร้า
app.put("/api/cart/update/:cartItemId", authenticateToken, async (req, res) => {
  const { quantity } = req.body;
  const { cartItemId } = req.params;
  const userId = req.user.userId;

  // ตรวจสอบว่าจำนวนสินค้า
  if (!quantity || quantity < 1) {
    return res.status(400).json({ message: "จำนวนสินค้าต้องมากกว่า 0" });
  }

  try {
    // ตรวจสอบให้แน่ใจว่าผู้ใช้เป็นเจ้าของ cart item นี้จริง ๆ เพื่อความปลอดภัย
    const updateSql =
      "UPDATE CartItem SET quantity = ? WHERE cart_item_id = ? AND user_id = ?";
    const [result] = await db.query(updateSql, [quantity, cartItemId, userId]);

    if (result.affectedRows === 0) {
      return res
        .status(404)
        .json({ message: "ไม่พบรายการสินค้านี้ในตะกร้าของคุณ" });
    }

    res.status(200).json({ message: "อัปเดตจำนวนสินค้าสำเร็จ" });
  } catch (error) {
    console.error("Update Cart Error:", error);
    res.status(500).json({ message: "เกิดข้อผิดพลาดในการอัปเดตสินค้า" });
  }
});

// ลบสินค้าออกจากตะกร้า
app.delete(
  "/api/cart/delete/:cartItemId",
  authenticateToken,
  async (req, res) => {
    const { cartItemId } = req.params;
    const userId = req.user.userId;

    try {
      // ตรวจสอบให้แน่ใจว่าผู้ใช้เป็นเจ้าของ cart item นี้จริง ๆ
      const deleteSql =
        "DELETE FROM CartItem WHERE cart_item_id = ? AND user_id = ?";
      const [result] = await db.query(deleteSql, [cartItemId, userId]);

      if (result.affectedRows === 0) {
        return res
          .status(404)
          .json({ message: "ไม่พบรายการสินค้านี้ในตะกร้าของคุณ" });
      }

      res.status(200).json({ message: "ลบสินค้าออกจากตะกร้าสำเร็จ" });
    } catch (error) {
      console.error("Delete Cart Error:", error);
      res.status(500).json({ message: "เกิดข้อผิดพลาดในการลบสินค้า" });
    }
  }
);

//  GET ค้นหาสินค้าตามชื่อหรือรายละเอียด
// app.get("/api/products/search", async (req, res) => {
//   const searchTerm = req.query.q;

//   if (!searchTerm) {
//     return res.status(200).json([]);
//   }

//   try {
//     const searchQuery = `%${searchTerm}%`;

//     const sql = "SELECT * FROM Product WHERE name LIKE ? OR description LIKE ?";
//     const [products] = await db.query(sql, [searchQuery, searchQuery]);

//     res.status(200).json(products);
//   } catch (error) {
//     console.error("Search Product Error:", error);
//     res.status(500).json({ message: "เกิดข้อผิดพลาดในการค้นหาสินค้า" });
//   }
// });

// GET ค้นหาสินค้าตามชื่อ
app.get("/api/products/search", async (req, res) => {
  const searchTerm = req.query.q;

  if (!searchTerm) {
    return res.status(200).json([]);
  }
  try {
    const searchQuery = `%${searchTerm}%`;
    // ค้นหาจาก 4 คอลัมน์ (ไทย 2, อังกฤษ 2)
    const sql = `
        SELECT * FROM Product 
        WHERE sales_status = 1 AND (
            name LIKE ? OR 
            name_en LIKE ?
        )
    `;
    const [products] = await db.query(sql, [
      searchQuery,
      searchQuery,
      searchQuery,
      searchQuery,
    ]);
    res.status(200).json(products);
  } catch (error) {
    res.status(500).json({ message: "เกิดข้อผิดพลาดในการค้นหาสินค้า" });
  }
});

//  API สำหรับดึงข้อมูลโปรไฟล์ล่าสุดของผู้ใช้ที่ล็อกอินอยู่
app.get("/api/user/profile", authenticateToken, async (req, res) => {
  const userId = req.user.userId;

  try {
    const sql = `
            SELECT user_id, username, email, role_id, points, phone, address 
            FROM Users 
            WHERE user_id = ?
        `;
    const [users] = await db.query(sql, [userId]);

    if (users.length === 0) {
      return res.status(404).json({ message: "User not found" });
    }

    const user = users[0];
    const [roles] = await db.query(
      "SELECT role_name FROM Role WHERE role_id = ?",
      [user.role_id]
    );

    const userInfo = {
      ...user,
      role: roles[0].role_name,
    };
    delete userInfo.role_id;

    res.status(200).json(userInfo);
  } catch (error) {
    console.error("Get Profile Error:", error);
    res.status(500).json({ message: "เกิดข้อผิดพลาดในการดึงข้อมูลโปรไฟล์" });
  }
});

// POST: สร้างคำสั่งซื้อใหม่
app.post("/api/orders", authenticateToken, async (req, res) => {
  const { items, totalPrice, paymentMethod, shippingInfo } = req.body;
  const userId = req.user.userId;
  const connection = await db.getConnection();

  try {
    await connection.beginTransaction();

    // 1. สร้าง Order หลัก
    const orderSql = ` INSERT INTO Orders (user_id, shipping_name, shipping_phone, shipping_address, total_price, status, payment_method) VALUES (?, ?, ?, ?, ?, 'pending_payment', ?)`;
    const [orderResult] = await connection.query(orderSql, [
      userId,
      shippingInfo.name,
      shippingInfo.phone,
      shippingInfo.address,
      totalPrice,
      paymentMethod,
    ]);
    const newOrderId = orderResult.insertId;

    // 2. เพิ่มรายการสินค้าใน Order_items
    const orderItemsSql =
      "INSERT INTO Order_items (order_id, product_id, quantity, current_price) VALUES ?";
    const orderItemsValues = items.map((item) => [
      newOrderId,
      item.product_id,
      item.quantity,
      item.price,
    ]);
    await connection.query(orderItemsSql, [orderItemsValues]);

    // 3. ลบสินค้าออกจากตะกร้า
    const cartItemIds = items.map((item) => item.cart_item_id);
    const deleteCartSql =
      "DELETE FROM CartItem WHERE user_id = ? AND cart_item_id IN (?)";
    await connection.query(deleteCartSql, [userId, cartItemIds]);

    await connection.commit();

    res
      .status(201)
      .json({ message: "Order created successfully", orderId: newOrderId });
  } catch (error) {
    await connection.rollback();
    console.error("Create Order Error:", error);
    res.status(500).json({ message: "Failed to create order" });
  } finally {
    connection.release();
  }
});

// NEW: API สำหรับ "ซื้อทันที"
app.post("/api/orders/buy-now", authenticateToken, async (req, res) => {
  const { item, totalPrice, paymentMethod, shippingInfo } = req.body;
  const userId = req.user.userId;
  const connection = await db.getConnection();

  try {
    await connection.beginTransaction();

    // 1. สร้าง Order หลัก
    const orderSql = `
            INSERT INTO Orders (user_id, shipping_name, shipping_phone, shipping_address, total_price, status, payment_method)
            VALUES (?, ?, ?, ?, ?, 'pending_payment', ?)
        `;
    const [orderResult] = await connection.query(orderSql, [
      userId,
      shippingInfo.name,
      shippingInfo.phone,
      shippingInfo.address,
      totalPrice,
      paymentMethod,
    ]);
    const newOrderId = orderResult.insertId;

    // 2. เพิ่มรายการสินค้าชิ้นเดียวใน Order_items
    const orderItemsSql =
      "INSERT INTO Order_items (order_id, product_id, quantity, current_price) VALUES (?, ?, ?, ?)";
    await connection.query(orderItemsSql, [
      newOrderId,
      item.product_id,
      item.quantity,
      item.price,
    ]);

    // *** ไม่มีการลบของในตะกร้า ***

    await connection.commit();

    res
      .status(201)
      .json({ message: "Order created successfully", orderId: newOrderId });
  } catch (error) {
    await connection.rollback();
    console.error("Buy Now Order Error:", error);
    res.status(500).json({ message: "Failed to create buy now order" });
  } finally {
    connection.release();
  }
});

// PUT: อัปโหลดสลิปสำหรับออเดอร์ (อัปเดตให้ใช้ R2)
app.put(
  "/api/orders/:orderId/receipt",
  [authenticateToken, uploadR2.single("receipt")],
  async (req, res) => {
    const { orderId } = req.params;
    const userId = req.user.userId;

    if (!req.file) {
      return res.status(400).json({ message: "No receipt image uploaded." });
    }
    const receiptImageUrl = `${process.env.R2_PUBLIC_URL}/${req.file.key}`;

    try {
      // 1. ดึงข้อมูลราคารวม (total_price) ของออเดอร์นี้มาก่อน
      const [orderData] = await db.query(
        "SELECT total_price FROM Orders WHERE order_id = ? AND user_id = ?",
        [orderId, userId]
      );

      if (orderData.length === 0) {
        return res
          .status(404)
          .json({ message: "Order not found or access denied." });
      }
      const totalPrice = orderData[0].total_price;

      // 2. อัปเดตฐานข้อมูล
      const sql = `UPDATE Orders SET receipt_image_url = ?, pay_date = CURRENT_TIMESTAMP, status = 'pending_verification' WHERE order_id = ? AND user_id = ?`;
      const [result] = await db.query(sql, [receiptImageUrl, orderId, userId]);

      if (result.affectedRows === 0) {
        return res
          .status(404)
          .json({ message: "Order not found or access denied." });
      }

      // 3. สร้างข้อความแจ้งเตือนโดยใช้ totalPrice ที่ดึงมา
      const message = `\n มีการแจ้งชำระเงิน\nหมายเลข: #${orderId}\nยอดรวม: ${totalPrice.toLocaleString()} บาท\nกรุณาตรวจสอบสลิป`;
      sendLineMessage(process.env.LINE_GROUP_ID, message);

      res.status(200).json({ message: "Receipt uploaded successfully." });
    } catch (error) {
      console.error("Upload Receipt Error:", error);
      res.status(500).json({ message: "Failed to upload receipt." });
    }
  }
);

// GET: ดึงประวัติคำสั่งซื้อของลูกค้าที่ล็อกอินอยู่ (เวอร์ชันอัปเกรด)
app.get("/api/orders/my-history", authenticateToken, async (req, res) => {
  const userId = req.user.userId;
  try {
    // 1. ดึงข้อมูล Order หลักทั้งหมดของ User
    const ordersSql = `
            SELECT order_id, total_price, status, order_date
            FROM Orders
            WHERE user_id = ?
            ORDER BY order_date DESC
        `;
    const [orders] = await db.query(ordersSql, [userId]);

    if (orders.length === 0) {
      return res.json([]); // ถ้าไม่มีออเดอร์ ส่ง array ว่างกลับไป
    }

    // 2. ดึงรายการสินค้าทั้งหมดที่อยู่ใน Order เหล่านั้นในครั้งเดียว
    const orderIds = orders.map((o) => o.order_id);
    const itemsSql = `
            SELECT oi.*, p.name as product_name, p.image_url
            FROM Order_items oi
            JOIN Product p ON oi.product_id = p.product_id
            WHERE oi.order_id IN (?)
        `;
    const [items] = await db.query(itemsSql, [orderIds]);

    // 3. นำรายการสินค้าไปใส่ในแต่ละ Order ให้ถูกต้อง
    const ordersWithItems = orders.map((order) => ({
      ...order,
      items: items.filter((item) => item.order_id === order.order_id),
    }));

    res.json(ordersWithItems);
  } catch (error) {
    console.error("Get Order History Error:", error);
    res.status(500).json({ message: "Error fetching order history" });
  }
});

// GET: ดึงข้อมูล Order เดียวของลูกค้าที่ล็อกอินอยู่
app.get(
  "/api/orders/my-history/:orderId",
  authenticateToken,
  async (req, res) => {
    const { orderId } = req.params;
    const userId = req.user.userId;

    try {
      const sql = `
            SELECT * FROM Orders 
            WHERE order_id = ? AND user_id = ?
        `;
      const [orders] = await db.query(sql, [orderId, userId]);

      if (orders.length === 0) {
        return res
          .status(404)
          .json({ message: "Order not found or access denied" });
      }
      res.json(orders[0]);
    } catch (error) {
      res.status(500).json({ message: "Error fetching order details" });
    }
  }
);

// ตรวจสอบ Role Admin/Employee
const authorizeAdmin = (req, res, next) => {
  const allowedRoles = ["admin", "employee"];
  if (req.user && allowedRoles.includes(req.user.role)) {
    next(); // ถ้า Role ถูกต้อง ให้ไปต่อ
  } else {
    // ถ้า Role ไม่ถูกต้อง ให้ปฏิเสธ
    res.status(403).json({ message: "Forbidden: Access is denied" });
  }
};

// NEW: Middleware สำหรับ Super Admin เท่านั้น
const authorizeSuperAdmin = (req, res, next) => {
  if (req.user && req.user.role === "admin") {
    next();
  } else {
    res.status(403).json({ message: "Forbidden: Requires admin role" });
  }
};

// --- Admin APIs ---

// ดึงข้อมูล Categories ทั้งหมดสำหรับใช้ในฟอร์ม
app.get(
  "/api/categories",
  [authenticateToken, authorizeAdmin],
  async (req, res) => {
    try {
      const [categories] = await db.query(
        "SELECT * FROM Category ORDER BY category_name"
      );
      res.json(categories);
    } catch (error) {
      res.status(500).json({ message: "Error fetching categories" });
    }
  }
);

// POST: สร้างสินค้าใหม่
app.post(
  "/api/admin/products",
  [authenticateToken, authorizeAdmin, uploadR2.single("image")],
  async (req, res) => {
    const {
      name,
      name_en,
      price,
      description,
      description_en,
      category_id,
      recommend_status,
      sales_status,
    } = req.body;
    const imageUrl = req.file
      ? `${process.env.R2_PUBLIC_URL}/${req.file.key}`
      : null;
    try {
      const sql = `INSERT INTO Product (name, name_en, price, description, description_en, category_id, image_url, recommend_status, sales_status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`;
      const [result] = await db.query(sql, [
        name,
        name_en,
        price,
        description,
        description_en,
        category_id,
        imageUrl,
        recommend_status,
        sales_status,
      ]);
      res.status(201).json({
        message: "Product created successfully",
        productId: result.insertId,
      });
    } catch (error) {
      res.status(500).json({ message: "Error creating product" });
    }
  }
);

// GET: ดึงข้อมูลสินค้าทั้งหมดสำหรับแสดงในตารางจัดการ
app.get(
  "/api/admin/products",
  [authenticateToken, authorizeAdmin],
  async (req, res) => {
    try {
      const sql = `
            SELECT p.*, c.category_name 
            FROM Product p 
            LEFT JOIN Category c ON p.category_id = c.category_id
            ORDER BY p.product_id DESC
        `;
      const [products] = await db.query(sql);
      res.json(products);
    } catch (error) {
      console.error("Admin Get Products Error:", error);
      res.status(500).json({ message: "Error fetching products for admin" });
    }
  }
);

// PUT: อัปเดตข้อมูลสินค้า
app.put(
  "/api/admin/products/:id",
  [authenticateToken, authorizeAdmin, uploadR2.single("image")],
  async (req, res) => {
    const { id } = req.params;
    // เพิ่ม name_en, description_en
    const {
      name,
      name_en,
      price,
      description,
      description_en,
      category_id,
      recommend_status,
      sales_status,
      existing_image_url,
    } = req.body;
    let imageUrl = existing_image_url || null;
    if (req.file) {
      imageUrl = `${process.env.R2_PUBLIC_URL}/${req.file.key}`;
      if (existing_image_url) {
        await deleteFileFromR2(existing_image_url);
      }
    }
    try {
      const sql = `UPDATE Product SET name = ?, name_en = ?, price = ?, description = ?, description_en = ?, category_id = ?, image_url = ?, recommend_status = ?, sales_status = ? WHERE product_id = ?`;
      await db.query(sql, [
        name,
        name_en,
        price,
        description,
        description_en,
        category_id,
        imageUrl,
        recommend_status,
        sales_status,
        id,
      ]);
      res.status(200).json({ message: "Product updated successfully" });
    } catch (error) {
      res.status(500).json({ message: "Error updating product" });
    }
  }
);

// DELETE: ลบสินค้าตาม ID
app.delete(
  "/api/admin/products/:id",
  [authenticateToken, authorizeAdmin],
  async (req, res) => {
    const { id } = req.params;
    try {
      await db.query("DELETE FROM Product WHERE product_id = ?", [id]);
      res.status(200).json({ message: "Product deleted successfully" });
    } catch (error) {
      console.error(error);
      if (error.code === "ER_ROW_IS_REFERENCED_2") {
        return res.status(400).json({
          message: "ไม่สามารถลบสินค้าได้ เนื่องจากมีอยู่ในตะกร้าของผู้ใช้อื่น",
        });
      }
      res.status(500).json({ message: "Error deleting product" });
    }
  }
);

// GET: ดึงข้อมูลคำสั่งซื้อทั้งหมดสำหรับแอดมิน
app.get(
  "/api/admin/orders",
  [authenticateToken, authorizeAdmin],
  async (req, res) => {
    try {
      const sql = `
            SELECT o.*, u.username 
            FROM Orders o
            JOIN Users u ON o.user_id = u.user_id
            ORDER BY o.order_date DESC
        `;
      const [orders] = await db.query(sql);
      res.json(orders);
    } catch (error) {
      console.error("Get Orders Error:", error);
      res.status(500).json({ message: "Error fetching orders" });
    }
  }
);

// PUT: อัปเดตสถานะของคำสั่งซื้อ
app.put(
  "/api/admin/orders/:orderId/status",
  [authenticateToken, authorizeAdmin],
  async (req, res) => {
    const { orderId } = req.params;
    const { status } = req.body;

    try {
      // อัปเดตสถานะ และอัปเดต pay_date ถ้าสถานะเปลี่ยนเป็น 'processing'
      const sql = `
            UPDATE Orders 
            SET status = ?, pay_date = CASE WHEN ? = 'processing' AND pay_date IS NULL THEN CURRENT_TIMESTAMP ELSE pay_date END
            WHERE order_id = ?
        `;
      await db.query(sql, [status, status, orderId]);
      res.status(200).json({ message: "Order status updated successfully" });
    } catch (error) {
      console.error("Update Order Status Error:", error);
      res.status(500).json({ message: "Error updating order status" });
    }
  }
);

// GET: ดึงข้อมูลรายละเอียดของออเดอร์เดียว (สำหรับแอดมิน)
app.get(
  "/api/admin/orders/:orderId",
  [authenticateToken, authorizeAdmin],
  async (req, res) => {
    const { orderId } = req.params;

    try {
      // --- จุดที่แก้ไข ---
      // เปลี่ยนจากการ SELECT u.phone, u.address
      // มาเป็น o.shipping_name, o.shipping_phone, o.shipping_address
      const orderSql = `
            SELECT 
                o.*, 
                u.username, 
                u.email,
                o.shipping_name,
                o.shipping_phone,
                o.shipping_address
            FROM Orders o
            JOIN Users u ON o.user_id = u.user_id
            WHERE o.order_id = ?
        `;
      // --- จบจุดที่แก้ไข ---
      const [orders] = await db.query(orderSql, [orderId]);

      if (orders.length === 0) {
        return res.status(404).json({ message: "Order not found" });
      }

      const itemsSql = `
            SELECT oi.*, p.name as product_name
            FROM Order_items oi
            JOIN Product p ON oi.product_id = p.product_id
            WHERE oi.order_id = ?
        `;
      const [items] = await db.query(itemsSql, [orderId]);

      const orderDetails = {
        ...orders[0],
        items: items,
      };

      res.json(orderDetails);
    } catch (error) {
      console.error("Get Order Details Error:", error);
      res.status(500).json({ message: "Error fetching order details" });
    }
  }
);

// GET: ดึงรายชื่อผู้ใช้ทั้งหมด (เวอร์ชันอัปเกรด: ค้นหาได้)
app.get(
  "/api/admin/users",
  [authenticateToken, authorizeSuperAdmin],
  async (req, res) => {
    try {
      const { q } = req.query; // รับค่า q จาก query string

      let sql = `
            SELECT u.user_id, u.username, u.email, r.role_name
            FROM Users u
            JOIN Role r ON u.role_id = r.role_id
        `;
      const params = [];

      if (q) {
        sql += ` WHERE u.username LIKE ? OR u.email LIKE ?`;
        params.push(`%${q}%`, `%${q}%`);
      }

      sql += ` ORDER BY u.user_id`;

      const [users] = await db.query(sql, params);
      res.json(users);
    } catch (error) {
      res.status(500).json({ message: "Error fetching users" });
    }
  }
);

// GET: ดึงข้อมูล Role ทั้งหมด (Admin Only)
app.get(
  "/api/admin/roles",
  [authenticateToken, authorizeSuperAdmin],
  async (req, res) => {
    try {
      const [roles] = await db.query("SELECT * FROM Role ORDER BY role_id");
      res.json(roles);
    } catch (error) {
      res.status(500).json({ message: "Error fetching roles" });
    }
  }
);

// PUT: อัปเดต Role ของผู้ใช้ (Admin Only)
app.put(
  "/api/admin/users/:userId/role",
  [authenticateToken, authorizeSuperAdmin],
  async (req, res) => {
    const { userId } = req.params;
    const { roleId } = req.body; // เราจะส่ง role_id (ตัวเลข) มา

    try {
      await db.query("UPDATE Users SET role_id = ? WHERE user_id = ?", [
        roleId,
        userId,
      ]);
      res.status(200).json({ message: "User role updated successfully" });
    } catch (error) {
      res.status(500).json({ message: "Error updating user role" });
    }
  }
);

// --- Admin Category Management APIs ---

// POST: สร้างประเภทสินค้าใหม่ (Admin Only)
app.post(
  "/api/admin/categories",
  [authenticateToken, authorizeSuperAdmin],
  async (req, res) => {
    const { category_name, category_name_en } = req.body;
    if (!category_name) {
      return res.status(400).json({ message: "Category name is required" });
    }
    try {
      await db.query(
        "INSERT INTO Category (category_name, category_name_en) VALUES (?, ?)",
        [category_name, category_name_en]
      );
      res.status(201).json({ message: "Category created successfully" });
    } catch (error) {
      res.status(500).json({ message: "Error creating category" });
    }
  }
);

// PUT: อัปเดตชื่อประเภทสินค้า (Admin Only)
app.put(
  "/api/admin/categories/:id",
  [authenticateToken, authorizeSuperAdmin],
  async (req, res) => {
    const { id } = req.params;
    // เพิ่ม category_name_en
    const { category_name, category_name_en } = req.body;
    if (!category_name) {
      return res.status(400).json({ message: "Category name is required" });
    }
    try {
      // เพิ่ม field ใหม่ในคำสั่ง UPDATE
      await db.query(
        "UPDATE Category SET category_name = ?, category_name_en = ? WHERE category_id = ?",
        [category_name, category_name_en, id]
      );
      res.status(200).json({ message: "Category updated successfully" });
    } catch (error) {
      res.status(500).json({ message: "Error updating category" });
    }
  }
);

// DELETE: ลบประเภทสินค้า (Admin Only)
app.delete(
  "/api/admin/categories/:id",
  [authenticateToken, authorizeSuperAdmin],
  async (req, res) => {
    const { id } = req.params;
    try {
      await db.query("DELETE FROM Category WHERE category_id = ?", [id]);
      res.status(200).json({ message: "Category deleted successfully" });
    } catch (error) {
      // จัดการกรณีที่มีสินค้าใช้ Category นี้อยู่
      if (error.code === "ER_ROW_IS_REFERENCED_2") {
        return res.status(400).json({
          message: "ไม่สามารถลบได้ เนื่องจากมีสินค้าใช้ประเภทนี้อยู่",
        });
      }
      res.status(500).json({ message: "Error deleting category" });
    }
  }
);

// --- Store Information APIs ---

// GET: ดึงข้อมูลร้านค้า (เวอร์ชันอัปเดต: รองรับตารางว่าง)
app.get("/api/store-info", async (req, res) => {
  try {
    const [rows] = await db.query("SELECT * FROM StoreInfo WHERE id = 1");
    // ถ้าไม่เจอข้อมูล ให้ส่งอ็อบเจกต์เปล่ากลับไปพร้อม Status 200
    if (rows.length === 0) {
      return res.json(null); // ส่ง null กลับไป บอกว่าไม่มีข้อมูล
    }
    res.json(rows[0]);
  } catch (error) {
    res.status(500).json({ message: "Error fetching store information" });
  }
});

// PUT: อัปเดตข้อมูลร้านค้า (อัปเดตให้ใช้ R2)
app.put(
  "/api/store-info",
  [authenticateToken, authorizeAdmin, uploadR2.single("image")],
  async (req, res) => {
    const {
      name,
      address,
      phone,
      email,
      image_url,
      map_url,
      facebook_url,
      youtube_url,
      existing_image_url,
    } = req.body;

    let imageUrl = existing_image_url || null;
    if (req.file) {
      imageUrl = `${process.env.R2_PUBLIC_URL}/${req.file.key}`;

      if (existing_image_url) {
        await deleteFileFromR2(existing_image_url);
      }
    }

    try {
      const [rows] = await db.query("SELECT id FROM StoreInfo WHERE id = 1");
      if (rows.length > 0) {
        const sql = `
                UPDATE StoreInfo SET name = ?, address = ?, phone = ?, email = ?, 
                image_url = ?, map_url = ?, facebook_url = ?, youtube_url = ?
                WHERE id = 1
            `;
        await db.query(sql, [
          name,
          address,
          phone,
          email,
          imageUrl,
          map_url,
          facebook_url,
          youtube_url,
        ]);
      } else {
        const sql = `
                INSERT INTO StoreInfo (id, name, address, phone, email, image_url, map_url, facebook_url, youtube_url)
                VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?)
            `;
        await db.query(sql, [
          name,
          address,
          phone,
          email,
          imageUrl,
          map_url,
          facebook_url,
          youtube_url,
        ]);
      }
      res.status(200).json({ message: "Store information saved successfully" });
    } catch (error) {
      console.error("Update Store Info Error:", error);
      res.status(500).json({ message: "Error saving store information" });
    }
  }
);

// PUT: อัปโหลด/เปลี่ยน QR Code (Admin Only)
app.put(
  "/api/store-info/qr-code",
  [authenticateToken, authorizeAdmin, uploadR2.single("qr_code")],
  async (req, res) => {
    if (!req.file) {
      return res.status(400).json({ message: "No QR code image uploaded." });
    }

    const newQrCodeUrl = `${process.env.R2_PUBLIC_URL}/${req.file.key}`;

    try {
      // 1. ดึง URL ของ QR Code เก่า (ถ้ามี) เพื่อนำไปลบ
      const [rows] = await db.query(
        "SELECT qr_code_url FROM StoreInfo WHERE id = 1"
      );
      if (rows.length > 0 && rows[0].qr_code_url) {
        await deleteFileFromR2(rows[0].qr_code_url);
      }

      // 2. อัปเดตฐานข้อมูลด้วย URL ของ QR Code ใหม่
      await db.query("UPDATE StoreInfo SET qr_code_url = ? WHERE id = 1", [
        newQrCodeUrl,
      ]);

      res.status(200).json({
        message: "QR code updated successfully",
        qr_code_url: newQrCodeUrl,
      });
    } catch (error) {
      console.error("Update QR Code Error:", error);
      res.status(500).json({ message: "Error updating QR code." });
    }
  }
);

// ส่งข้อความผ่าน Messaging API
const sendLineMessage = async (groupId, messageText) => {
  const channelAccessToken = process.env.LINE_CHANNEL_ACCESS_TOKEN;
  if (!channelAccessToken || !groupId) {
    console.log("LINE Messaging API credentials not set, skipping message.");
    return;
  }

  try {
    await axios.post(
      "https://api.line.me/v2/bot/message/push",
      {
        to: groupId,
        messages: [
          {
            type: "text",
            text: messageText,
          },
        ],
      },
      {
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${channelAccessToken}`,
        },
      }
    );
    console.log("LINE push message sent successfully.");
  } catch (error) {
    console.error(
      "Error sending LINE push message:",
      error.response ? error.response.data.message : error.message
    );
  }
};

const PORT = process.env.API_PORT || 3001;
app.listen(PORT, () => {
  console.log(`Backend API server is running at http://localhost:${PORT}`);
});
