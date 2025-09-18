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
const axios = require("axios");

const app = express();
app.use(cors());
app.use(express.json());

const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET;

//  R2 Client and Multer S3 Setup ---
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
      if (req.path.includes("/categories")) folder = "categories/";
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
    if (!(await bcrypt.compare(password, user.password))) {
      return res
        .status(401)
        .json({ message: "ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง" });
    }

    const payload = {
      userId: user.user_id,
      username: user.username,
      role: user.role_name,
    };

    // กำหนดอายุ accessToken ตาม role
    const accessTokenExpiresIn =
      user.role_name === "admin" || user.role_name === "employee"
        ? "12h"
        : "1h";

    const accessToken = jwt.sign(payload, process.env.JWT_SECRET, {
      expiresIn: accessTokenExpiresIn,
    });

    // Refresh Token มีอายุยาวเสมอ (เช่น 7 วัน)
    const refreshToken = jwt.sign(payload, JWT_REFRESH_SECRET, {
      expiresIn: "7d",
    });

    const userInfo = {
      userId: user.user_id,
      username: user.username,
      email: user.email,
      role: user.role_name,
      points: user.points,
    };

    res.status(200).json({
      message: "ล็อกอินสำเร็จ!",
      accessToken, // ส่ง accessToken กลับไป
      refreshToken, // ส่ง refreshToken กลับไปด้วย
      user: userInfo,
    });
  } catch (error) {
    console.error("Database Error:", error);
    return res.status(500).json({ message: "เกิดข้อผิดพลาดในเซิร์ฟเวอร์" });
  }
});

// API Endpoint สำหรับขอ Access Token ใหม่
app.post("/api/token/refresh", (req, res) => {
  const { refreshToken } = req.body;

  if (!refreshToken) {
    return res.status(401).json({ message: "Refresh Token is required" });
  }

  jwt.verify(refreshToken, JWT_REFRESH_SECRET, (err, user) => {
    if (err) {
      // ถ้า Refresh Token ผิดพลาด (หมดอายุ, ไม่ถูกต้อง) ให้ส่ง 403
      return res
        .status(403)
        .json({ message: "Refresh Token is invalid or expired" });
    }

    // ถ้าถูกต้อง สร้าง Access Token ใหม่ตาม Role
    const payload = {
      userId: user.userId,
      username: user.username,
      role: user.role,
    };
    const accessTokenExpiresIn =
      user.role === "admin" || user.role === "employee" ? "12h" : "1h";

    const newAccessToken = jwt.sign(payload, process.env.JWT_SECRET, {
      expiresIn: accessTokenExpiresIn,
    });

    res.json({ accessToken: newAccessToken });
  });
});

// สร้าง Middleware สำหรับตรวจสอบ Token
// Middleware สำหรับตรวจสอบ JWT
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (token == null) {
    return res
      .status(401)
      .json({ message: "A token is required for authentication" });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      // ถ้า Token ไม่ถูกต้อง หรือหมดอายุ ให้ส่ง 401 Unauthorized กลับไปทันที
      // เพื่อให้ Interceptor ฝั่ง Frontend ทำงาน
      return res.status(401).json({ message: "Token is invalid or expired" });
    }
    // ถ้า Token ถูกต้อง ให้แนบข้อมูล user ไปกับ request แล้วทำงานต่อไป
    req.user = user;
    next();
  });
};

// --- API สำหรับฝั่งลูกค้า---

// API Endpoint สำหรับดึงข้อมูลสินค้าทั้งหมด
app.get("/api/products", async (req, res) => {
  try {
    const { category, recommended } = req.query;

    let sql = `
        SELECT 
            p.*, 
            c.category_name,
            (EXISTS(SELECT 1 FROM ProductOptions po WHERE po.product_id = p.product_id)) AS has_options
        FROM Product p 
        LEFT JOIN Category c ON p.category_id = c.category_id 
        WHERE p.sales_status = 1
    `;
    const params = [];

    if (category) {
      sql += " AND p.category_id = ?";
      params.push(category);
    }

    if (recommended === "true") {
      sql += " AND p.recommend_status = 1";
    }

    sql += " ORDER BY RAND()";

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
            SELECT category_id, category_name, category_name_en, icon_url FROM Category 
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
  const { id } = req.params;
  try {
    const productSql = "SELECT * FROM Product WHERE product_id = ?";
    const [products] = await db.query(productSql, [id]);

    if (products.length === 0) {
      return res.status(404).json({ message: "ไม่พบสินค้าชิ้นนี้" });
    }

    const product = products[0];

    const optionsSql =
      "SELECT option_id, option_name, option_name_en FROM ProductOptions WHERE product_id = ?";
    const [options] = await db.query(optionsSql, [id]);

    for (let option of options) {
      const valuesSql =
        "SELECT value_id, value_name, value_name_en FROM ProductOptionValues WHERE option_id = ?";
      const [values] = await db.query(valuesSql, [option.option_id]);
      option.values = values;
    }

    product.options = options;

    res.status(200).json(product);
  } catch (error) {
    console.error("Get Single Product Error:", error);
    res.status(500).json({ message: "เกิดข้อผิดพลาดในการดึงข้อมูลสินค้า" });
  }
});

// ฟังก์ชัน Helper สำหรับเปรียบเทียบ Object สองตัว
const areObjectsEqual = (obj1, obj2) => {
  // กรณีที่ทั้งสองเป็น null (ไม่มีตัวเลือก) ถือว่าเหมือนกัน
  if (obj1 === null && obj2 === null) return true;
  // กรณีที่ตัวใดตัวหนึ่งเป็น null อีกตัวไม่เป็น ถือว่าต่างกัน
  if (obj1 === null || obj2 === null) return false;

  const keys1 = Object.keys(obj1);
  const keys2 = Object.keys(obj2);

  // ถ้าจำนวน key ไม่เท่ากัน ถือว่าต่างกัน
  if (keys1.length !== keys2.length) return false;

  // เช็คทุก key-value pair ว่าตรงกันหรือไม่
  for (const key of keys1) {
    if (obj1[key] !== obj2[key]) {
      return false;
    }
  }

  return true;
};

// API สำหรับเพิ่มสินค้าลงตะกร้า (Logic ใหม่ทั้งหมดที่แม่นยำกว่าเดิม)
app.post("/api/cart/add", authenticateToken, async (req, res) => {
  const { productId, quantity, selectedOptions } = req.body;
  const userId = req.user.userId;

  if (!productId || !quantity) {
    return res.status(400).json({ message: "ข้อมูลไม่ครบถ้วน" });
  }

  const connection = await db.getConnection();
  try {
    // 1. จัดการ object ตัวเลือกที่เข้ามา (ถ้าไม่มีเลยให้เป็น null)
    const incomingOptions =
      selectedOptions && Object.keys(selectedOptions).length > 0
        ? selectedOptions
        : null;

    // 2. ดึงรายการสินค้าทั้งหมดที่มี product_id เดียวกันในตะกร้าของผู้ใช้ออกมา
    const findExistingSql =
      "SELECT * FROM CartItem WHERE user_id = ? AND product_id = ?";
    const [existingItems] = await connection.query(findExistingSql, [
      userId,
      productId,
    ]);

    let matchedItem = null;

    // 3. วนลูปเพื่อเปรียบเทียบตัวเลือกด้วย JavaScript
    for (const item of existingItems) {
      // item.selected_options จาก DB จะเป็น JSON string หรือ null
      if (areObjectsEqual(incomingOptions, item.selected_options)) {
        matchedItem = item;
        break; // เจอแล้ว ออกจาก loop ทันที
      }
    }

    // 4. ตัดสินใจว่าจะ UPDATE หรือ INSERT
    if (matchedItem) {
      // ถ้าเจอ: ให้อัปเดตจำนวนของรายการเดิม
      const newQuantity = matchedItem.quantity + quantity;
      const updateSql =
        "UPDATE CartItem SET quantity = ? WHERE cart_item_id = ?";
      await connection.query(updateSql, [
        newQuantity,
        matchedItem.cart_item_id,
      ]);
      res.status(200).json({ message: "อัปเดตจำนวนสินค้าในตะกร้าเรียบร้อย" });
    } else {
      // ถ้าไม่เจอ: ให้เพิ่มเป็นรายการใหม่
      const optionsJson = incomingOptions
        ? JSON.stringify(incomingOptions)
        : null;
      const insertSql =
        "INSERT INTO CartItem (user_id, product_id, quantity, selected_options) VALUES (?, ?, ?, ?)";
      await connection.query(insertSql, [
        userId,
        productId,
        quantity,
        optionsJson,
      ]);
      res.status(201).json({ message: "เพิ่มสินค้าลงตะกร้าสำเร็จ" });
    }
  } catch (error) {
    console.error("Cart Add Error:", error);
    res.status(500).json({ message: "เกิดข้อผิดพลาดในการเพิ่มสินค้าลงตะกร้า" });
  } finally {
    connection.release();
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
          ci.selected_options, 
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
  const { items, paymentMethod, shippingInfo, pointsToRedeem } = req.body;
  const userId = req.user.userId;
  const connection = await db.getConnection();
  try {
    await connection.beginTransaction();
    const subtotal = items.reduce(
      (sum, item) => sum + item.price * item.quantity,
      0
    );
    let finalTotalPrice = subtotal;
    let discountFromPoints = 0;
    const pointsToUse = parseInt(pointsToRedeem) || 0;
    if (pointsToUse > 0) {
      const [users] = await connection.query(
        "SELECT points FROM Users WHERE user_id = ? FOR UPDATE",
        [userId]
      );
      const currentUserPoints = users[0].points;
      if (currentUserPoints < pointsToUse || pointsToUse > subtotal) {
        await connection.rollback();
        return res
          .status(400)
          .json({ message: "แต้มไม่เพียงพอหรือใช้เกินราคาสินค้า" });
      }
      discountFromPoints = pointsToUse;
      finalTotalPrice = subtotal - discountFromPoints;
      await connection.query(
        "UPDATE Users SET points = points - ? WHERE user_id = ?",
        [pointsToUse, userId]
      );
    }
    const orderSql = `INSERT INTO Orders (user_id, subtotal, discount_amount, points_redeemed, total_price, shipping_name, shipping_phone, shipping_address, status, payment_method) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending_payment', ?)`;
    const [orderResult] = await connection.query(orderSql, [
      userId,
      subtotal,
      discountFromPoints,
      pointsToUse,
      finalTotalPrice,
      shippingInfo.name,
      shippingInfo.phone,
      shippingInfo.address,
      paymentMethod,
    ]);
    const newOrderId = orderResult.insertId;
    if (pointsToUse > 0) {
      await connection.query(
        "INSERT INTO PointHistory (user_id, order_id, points_change, transaction_type, description) VALUES (?, ?, ?, ?, ?)",
        [
          userId,
          newOrderId,
          -pointsToUse,
          "redeem",
          `แลกแต้มเป็นส่วนลด ${discountFromPoints.toLocaleString()} บาท สำหรับออเดอร์ #${newOrderId}`,
        ]
      );
    }
    const orderItemsSql =
      "INSERT INTO Order_items (order_id, product_id, quantity, current_price, selected_options) VALUES ?";
    const orderItemsValues = items.map((item) => [
      newOrderId,
      item.product_id,
      item.quantity,
      item.price,
      item.selected_options ? JSON.stringify(item.selected_options) : null,
    ]);
    await connection.query(orderItemsSql, [orderItemsValues]);
    const cartItemIds = items
      .filter((item) => item.cart_item_id)
      .map((item) => item.cart_item_id);
    if (cartItemIds.length > 0) {
      await connection.query(
        "DELETE FROM CartItem WHERE user_id = ? AND cart_item_id IN (?)",
        [userId, cartItemIds]
      );
    }
    await connection.commit();
    res
      .status(201)
      .json({ message: "Order created successfully", orderId: newOrderId });
  } catch (error) {
    await connection.rollback();
    console.error("Create Order Error:", error);
    res.status(500).json({ message: "Failed to create order from cart" });
  } finally {
    connection.release();
  }
});

// --- [จุดแก้ไขที่ 2] เพิ่ม API สำหรับ "ซื้อทันที" กลับเข้ามาใหม่ ---
app.post("/api/orders/buy-now", authenticateToken, async (req, res) => {
  const { item, paymentMethod, shippingInfo, pointsToRedeem } = req.body;
  const userId = req.user.userId;

  if (!item) {
    return res.status(400).json({ message: "ไม่มีข้อมูลสินค้า" });
  }

  const connection = await db.getConnection();
  try {
    await connection.beginTransaction();
    const subtotal = item.price * item.quantity;
    let finalTotalPrice = subtotal;
    let discountFromPoints = 0;
    const pointsToUse = parseInt(pointsToRedeem) || 0;

    if (pointsToUse > 0) {
      const [users] = await connection.query(
        "SELECT points FROM Users WHERE user_id = ? FOR UPDATE",
        [userId]
      );
      const currentUserPoints = users[0].points;
      if (currentUserPoints < pointsToUse || pointsToUse > subtotal) {
        await connection.rollback();
        return res
          .status(400)
          .json({ message: "แต้มไม่เพียงพอหรือใช้เกินราคาสินค้า" });
      }
      discountFromPoints = pointsToUse;
      finalTotalPrice = subtotal - discountFromPoints;
      await connection.query(
        "UPDATE Users SET points = points - ? WHERE user_id = ?",
        [pointsToUse, userId]
      );
    }

    const orderSql = `INSERT INTO Orders (user_id, subtotal, discount_amount, points_redeemed, total_price, shipping_name, shipping_phone, shipping_address, status, payment_method) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending_payment', ?)`;
    const [orderResult] = await connection.query(orderSql, [
      userId,
      subtotal,
      discountFromPoints,
      pointsToUse,
      finalTotalPrice,
      shippingInfo.name,
      shippingInfo.phone,
      shippingInfo.address,
      paymentMethod,
    ]);
    const newOrderId = orderResult.insertId;

    if (pointsToUse > 0) {
      await connection.query(
        "INSERT INTO PointHistory (user_id, order_id, points_change, transaction_type, description) VALUES (?, ?, ?, ?, ?)",
        [
          userId,
          newOrderId,
          -pointsToUse,
          "redeem",
          `แลกแต้มเป็นส่วนลด ${discountFromPoints.toLocaleString()} บาท สำหรับออเดอร์ #${newOrderId}`,
        ]
      );
    }

    const orderItemsSql =
      "INSERT INTO Order_items (order_id, product_id, quantity, current_price, selected_options) VALUES (?, ?, ?, ?, ?)";
    await connection.query(orderItemsSql, [
      newOrderId,
      item.product_id,
      item.quantity,
      item.price,
      item.selected_options ? JSON.stringify(item.selected_options) : null,
    ]);

    await connection.commit();
    res.status(201).json({
      message: "Buy Now Order created successfully",
      orderId: newOrderId,
    });
  } catch (error) {
    await connection.rollback();
    console.error("Create Buy Now Order Error:", error);
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

// GET: ดึงประวัติคำสั่งซื้อของลูกค้าที่ล็อกอินอยู่
app.get("/api/orders/my-history", authenticateToken, async (req, res) => {
  const userId = req.user.userId;
  try {
    const ordersSql = `
            SELECT order_id, total_price, status, order_date
            FROM Orders
            WHERE user_id = ?
            ORDER BY order_date DESC
        `;
    const [orders] = await db.query(ordersSql, [userId]);

    if (orders.length === 0) {
      return res.json([]);
    }

    const orderIds = orders.map((o) => o.order_id);
    const itemsSql = `
            SELECT oi.*, p.name as product_name, p.image_url
            FROM Order_items oi
            JOIN Product p ON oi.product_id = p.product_id
            WHERE oi.order_id IN (?)
        `;
    const [items] = await db.query(itemsSql, [orderIds]);

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

// PUT: อัปเดตข้อมูลโปรไฟล์ผู้ใช้
app.put("/api/user/profile", authenticateToken, async (req, res) => {
  const { username, email, phone, address } = req.body;
  const userId = req.user.userId;

  if (!username || !email) {
    return res.status(400).json({ message: "ชื่อผู้ใช้และอีเมลห้ามว่าง" });
  }

  try {
    const sql = `UPDATE Users SET username = ?, email = ?, phone = ?, address = ? WHERE user_id = ?`;
    await db.query(sql, [username, email, phone, address, userId]);
    res.status(200).json({ message: "อัปเดตข้อมูลสำเร็จ" });
  } catch (error) {
    if (error.code === "ER_DUP_ENTRY") {
      return res
        .status(409)
        .json({ message: "ชื่อผู้ใช้หรืออีเมลนี้มีอยู่แล้ว" });
    }
    console.error("Update Profile Error:", error);
    res.status(500).json({ message: "เกิดข้อผิดพลาดในการอัปเดตข้อมูล" });
  }
});

// PUT: เปลี่ยนรหัสผ่าน
app.put("/api/user/password", authenticateToken, async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  const userId = req.user.userId;

  if (!currentPassword || !newPassword) {
    return res.status(400).json({ message: "กรุณากรอกข้อมูลให้ครบถ้วน" });
  }

  try {
    const [users] = await db.query(
      "SELECT password FROM Users WHERE user_id = ?",
      [userId]
    );
    if (users.length === 0) {
      return res.status(404).json({ message: "ไม่พบผู้ใช้งาน" });
    }

    const user = users[0];
    const isPasswordMatch = await bcrypt.compare(
      currentPassword,
      user.password
    );

    if (!isPasswordMatch) {
      return res.status(401).json({ message: "รหัสผ่านปัจจุบันไม่ถูกต้อง" });
    }

    const hashedNewPassword = await bcrypt.hash(newPassword, 10);
    await db.query("UPDATE Users SET password = ? WHERE user_id = ?", [
      hashedNewPassword,
      userId,
    ]);

    res.status(200).json({ message: "เปลี่ยนรหัสผ่านสำเร็จ" });
  } catch (error) {
    console.error("Change Password Error:", error);
    res.status(500).json({ message: "เกิดข้อผิดพลาดในเซิร์ฟเวอร์" });
  }
});

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
      options, // รับ options ที่เป็น JSON string จาก frontend
    } = req.body;
    const imageUrl = req.file
      ? `${process.env.R2_PUBLIC_URL}/${req.file.key}`
      : null;

    const connection = await db.getConnection();

    try {
      await connection.beginTransaction();

      // 1. เพิ่มข้อมูลสินค้าหลักลงในตาราง Product
      const productSql = `INSERT INTO Product (name, name_en, price, description, description_en, category_id, image_url, recommend_status, sales_status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`;
      const [result] = await connection.query(productSql, [
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
      const newProductId = result.insertId;

      // 2. จัดการกับตัวเลือกสินค้า
      const productOptions = options ? JSON.parse(options) : [];
      for (const option of productOptions) {
        // ตรวจสอบว่ามีชื่อประเภทและมีค่าอย่างน้อย 1 ค่า
        if (option.name && option.values && option.values.length > 0) {
          // 2.1 เพิ่มชื่อประเภท (เช่น ขนาด) ลงในตาราง ProductOptions
          const optionSql =
            "INSERT INTO ProductOptions (product_id, option_name, option_name_en) VALUES (?, ?, ?)";
          const [optionResult] = await connection.query(optionSql, [
            newProductId,
            option.name,
            option.name_en || null,
          ]);

          const newOptionId = optionResult.insertId;

          // 2.2 เพิ่มค่าทั้งหมด (เช่น S, M, L) ลงในตาราง ProductOptionValues
          const valuesSql =
            "INSERT INTO ProductOptionValues (option_id, value_name, value_name_en) VALUES ?";
          const valuesToInsert = option.values.map((val) => [
            newOptionId,
            val.name,
            val.name_en || null,
          ]);
          if (valuesToInsert.length > 0) {
            await connection.query(valuesSql, [valuesToInsert]);
          }
        }
      }

      await connection.commit();
      res.status(201).json({
        message: "Product created successfully",
        productId: newProductId,
      });
    } catch (error) {
      await connection.rollback();
      console.error("Create Product Error:", error);
      res.status(500).json({ message: "Error creating product" });
    } finally {
      connection.release();
    }
  }
);

// GET: ดึงข้อมูลสินค้าทั้งหมดสำหรับแสดงในตารางจัดการ
app.get(
  "/api/admin/products",
  [authenticateToken, authorizeAdmin],
  async (req, res) => {
    const { q } = req.query; // รับค่าคำค้นหาจาก query string

    try {
      // เริ่มต้น SQL query พื้นฐาน
      let sql = `
            SELECT p.*, c.category_name 
            FROM Product p 
            LEFT JOIN Category c ON p.category_id = c.category_id
        `;
      const params = [];

      // ถ้ามีคำค้นหา (q) ส่งมา ให้เพิ่มเงื่อนไข WHERE เข้าไปใน SQL
      if (q) {
        sql += " WHERE (p.name LIKE ? OR p.name_en LIKE ?)";
        const searchTerm = `%${q}%`;
        params.push(searchTerm, searchTerm); // ค้นหาทั้งชื่อไทยและอังกฤษ
      }

      sql += " ORDER BY p.product_id DESC";

      const [products] = await db.query(sql, params);
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
      options,
    } = req.body;

    let imageUrl = existing_image_url || null;
    if (req.file) {
      imageUrl = `${process.env.R2_PUBLIC_URL}/${req.file.key}`;
      if (existing_image_url) {
        await deleteFileFromR2(existing_image_url);
      }
    }

    const connection = await db.getConnection();
    try {
      await connection.beginTransaction();

      // 1. อัปเดตข้อมูลสินค้าหลักในตาราง Product
      const productSql = `UPDATE Product SET name = ?, name_en = ?, price = ?, description = ?, description_en = ?, category_id = ?, image_url = ?, recommend_status = ?, sales_status = ? WHERE product_id = ?`;
      await connection.query(productSql, [
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

      // 2. ลบ Options และ Values เก่าทั้งหมดของสินค้านี้เพื่อความสะอาด
      // (การใช้ ON DELETE CASCADE ใน SQL ทำให้เมื่อลบจาก ProductOptions แล้ว ค่าใน ProductOptionValues จะถูกลบตามไปด้วย)
      await connection.query(
        "DELETE FROM ProductOptions WHERE product_id = ?",
        [id]
      );

      // 3. เพิ่ม Options และ Values ใหม่ทั้งหมดจากที่ส่งมา
      const productOptions = options ? JSON.parse(options) : [];
      for (const option of productOptions) {
        if (option.name && option.values && option.values.length > 0) {
          const optionSql =
            "INSERT INTO ProductOptions (product_id, option_name, option_name_en) VALUES (?, ?, ?)";
          const [optionResult] = await connection.query(optionSql, [
            id,
            option.name,
            option.name_en || null,
          ]);

          const newOptionId = optionResult.insertId;

          const valuesSql =
            "INSERT INTO ProductOptionValues (option_id, value_name, value_name_en) VALUES ?";
          const valuesToInsert = option.values.map((val) => [
            newOptionId,
            val.name,
            val.name_en || null,
          ]);

          if (valuesToInsert.length > 0) {
            await connection.query(valuesSql, [valuesToInsert]);
          }
        }
      }

      await connection.commit();
      res.status(200).json({ message: "Product updated successfully" });
    } catch (error) {
      await connection.rollback();
      console.error("Update Product Error:", error);
      res.status(500).json({ message: "Error updating product" });
    } finally {
      connection.release();
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

// GET: ดึงจำนวนออเดอร์ในแต่ละสถานะ
app.get(
  "/api/admin/orders/status-counts",
  [authenticateToken, authorizeAdmin],
  async (req, res) => {
    try {
      // ใช้ SQL เพื่อนับจำนวนออเดอร์ โดยจัดกลุ่มตามสถานะ
      const sql =
        "SELECT status, COUNT(*) as count FROM Orders GROUP BY status";
      const [results] = await db.query(sql);

      // แปลงผลลัพธ์จาก array เป็น object เพื่อให้ใช้ง่ายใน Frontend
      // เช่น { pending_payment: 5, processing: 2 }
      const counts = results.reduce((acc, row) => {
        acc[row.status] = row.count;
        return acc;
      }, {});

      res.json(counts);
    } catch (error) {
      console.error("Get Order Status Counts Error:", error);
      res.status(500).json({ message: "Error fetching order status counts" });
    }
  }
);

// GET: ดึงข้อมูลคำสั่งซื้อทั้งหมดสำหรับแอดมิน
app.get(
  "/api/admin/orders",
  [authenticateToken, authorizeAdmin],
  async (req, res) => {
    // 1. รับค่า status และ sortBy จาก query string
    const { status, sortBy } = req.query;

    try {
      let sql = `
            SELECT o.*, u.username 
            FROM Orders o
            LEFT JOIN Users u ON o.user_id = u.user_id
        `;
      const params = [];

      // 2. ถ้ามีการส่ง status มา ให้เพิ่มเงื่อนไข WHERE
      if (status && status !== "all") {
        sql += " WHERE o.status = ?";
        params.push(status);
      }

      // 3. กำหนดการเรียงลำดับ (Sort Order)
      // ถ้า sortBy เป็น 'asc' ให้เรียงจากเก่าไปใหม่, นอกนั้นให้เรียงจากใหม่ไปเก่า (default)
      const sortOrder = sortBy === "asc" ? "ASC" : "DESC";
      sql += ` ORDER BY o.order_date ${sortOrder}`;

      const [orders] = await db.query(sql, params);
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
    const connection = await db.getConnection(); // --- [เพิ่ม] ใช้ connection สำหรับ transaction

    try {
      // --- [เพิ่ม] เริ่มต้น Transaction ---
      await connection.beginTransaction();

      // 1. อัปเดตสถานะออเดอร์
      const updateStatusSql = `
            UPDATE Orders 
            SET status = ?, pay_date = CASE WHEN ? = 'processing' AND pay_date IS NULL THEN CURRENT_TIMESTAMP ELSE pay_date END
            WHERE order_id = ?
        `;
      await connection.query(updateStatusSql, [status, status, orderId]);

      // --- [เพิ่ม] Logic การให้แต้ม ---
      // 2. เช็คว่าสถานะที่เปลี่ยนเป็น 'processing' หรือไม่ (ซึ่งหมายถึงยืนยันการชำระเงินแล้ว)
      if (status === "processing") {
        // 2.1 ตรวจสอบก่อนว่าเคยให้แต้มสำหรับออเดอร์นี้ไปแล้วหรือยัง (ป้องกันการให้แต้มซ้ำ)
        const [historyCheck] = await connection.query(
          "SELECT COUNT(*) as count FROM PointHistory WHERE order_id = ? AND transaction_type = 'earn'",
          [orderId]
        );

        if (historyCheck[0].count === 0) {
          // 2.2 ดึงข้อมูล user_id และ total_price จากออเดอร์
          const [orderData] = await connection.query(
            "SELECT user_id, total_price FROM Orders WHERE order_id = ?",
            [orderId]
          );

          if (orderData.length > 0) {
            const { user_id, total_price } = orderData[0];

            // 2.3 คำนวณแต้ม (เฉพาะเมื่อมี user_id และยอดซื้อมากกว่า 0)
            if (user_id && total_price > 0) {
              const pointsToAdd = Math.floor(total_price / 10);
              if (pointsToAdd > 0) {
                // 2.4 อัปเดตแต้มในตาราง Users
                await connection.query(
                  "UPDATE Users SET points = points + ? WHERE user_id = ?",
                  [pointsToAdd, user_id]
                );
                // 2.5 บันทึกประวัติลงใน PointHistory
                await connection.query(
                  "INSERT INTO PointHistory (user_id, order_id, points_change, transaction_type, description) VALUES (?, ?, ?, ?, ?)",
                  [
                    user_id,
                    orderId,
                    pointsToAdd,
                    "earn",
                    `ได้รับแต้มจากออเดอร์ #${orderId}`,
                  ]
                );
              }
            }
          }
        }
      }
      // --- สิ้นสุด Logic การให้แต้ม ---

      // --- [เพิ่ม] ยืนยัน Transaction ---
      await connection.commit();
      res.status(200).json({ message: "Order status updated successfully" });
    } catch (error) {
      // --- [เพิ่ม] หากเกิด Error ให้ Rollback ---
      await connection.rollback();
      console.error("Update Order Status Error:", error);
      res.status(500).json({ message: "Error updating order status" });
    } finally {
      // --- [เพิ่ม] คืน connection สู่ pool ---
      connection.release();
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
      // เพิ่ม o.cash_received และ o.change_given เข้าไปใน SELECT statement
      const orderSql = `
            SELECT 
                o.*, 
                u.username, 
                u.email
            FROM Orders o
            LEFT JOIN Users u ON o.user_id = u.user_id
            WHERE o.order_id = ?
        `;
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

// GET: ดึงรายชื่อผู้ใช้ทั้งหมด
app.get(
  "/api/admin/users",
  [authenticateToken, authorizeSuperAdmin],
  async (req, res) => {
    try {
      const { q, roleId } = req.query; // รับค่า roleId จาก query string

      let sql = `
            SELECT u.user_id, u.username, u.email, r.role_name
            FROM Users u
            JOIN Role r ON u.role_id = r.role_id
        `;
      const params = [];
      const whereClauses = [];

      if (q) {
        whereClauses.push(`(u.username LIKE ? OR u.email LIKE ?)`);
        params.push(`%${q}%`, `%${q}%`);
      }

      if (roleId && roleId !== "all") {
        whereClauses.push(`u.role_id = ?`);
        params.push(roleId);
      }

      if (whereClauses.length > 0) {
        sql += ` WHERE ${whereClauses.join(" AND ")}`;
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

app.get(
  "/api/admin/categories",
  [authenticateToken, authorizeAdmin],
  async (req, res) => {
    try {
      const [categories] = await db.query(
        "SELECT * FROM Category ORDER BY category_id DESC"
      );
      res.json(categories);
    } catch (error) {
      res.status(500).json({ message: "Error fetching categories" });
    }
  }
);

// POST: สร้างประเภทสินค้าใหม่ (Admin Only)
app.post(
  "/api/admin/categories",
  [authenticateToken, authorizeAdmin, uploadR2.single("icon")], // <-- เพิ่ม middleware
  async (req, res) => {
    const { category_name, category_name_en } = req.body;
    if (!category_name) {
      return res.status(400).json({ message: "Category name is required" });
    }
    // ดึง URL ของไอคอนที่อัปโหลด (ถ้ามี)
    const iconUrl = req.file
      ? `${process.env.R2_PUBLIC_URL}/${req.file.key}`
      : null;

    try {
      await db.query(
        "INSERT INTO Category (category_name, category_name_en, icon_url) VALUES (?, ?, ?)",
        [category_name, category_name_en, iconUrl]
      );
      res.status(201).json({ message: "Category created successfully" });
    } catch (error) {
      res.status(500).json({ message: "Error creating category" });
    }
  }
);

// PUT: อัปเดตชื่อประเภทสินค้า
app.put(
  "/api/admin/categories/:id",
  [authenticateToken, authorizeAdmin, uploadR2.single("icon")],
  async (req, res) => {
    const { id } = req.params;
    const { category_name, category_name_en } = req.body;
    if (!category_name) {
      return res.status(400).json({ message: "Category name is required" });
    }

    // 1. เริ่มใช้ Connection จาก Pool เพื่อรองรับ Transaction
    const connection = await db.getConnection();

    try {
      // 2. เริ่มต้น Transaction
      await connection.beginTransaction();

      // 3. ดึง URL ของไอคอนเก่าจากฐานข้อมูลโดยตรง เพื่อความปลอดภัย
      const [oldCategoryData] = await connection.query(
        "SELECT icon_url FROM Category WHERE category_id = ?",
        [id]
      );
      const oldIconUrl =
        oldCategoryData.length > 0 ? oldCategoryData[0].icon_url : null;

      // 4. กำหนด URL ของไอคอนใหม่
      // ถ้ามีการอัปโหลดไฟล์ใหม่ ให้ใช้ URL ใหม่, ถ้าไม่ ให้ใช้ URL เดิม
      let newIconUrl = oldIconUrl;
      if (req.file) {
        newIconUrl = `${process.env.R2_PUBLIC_URL}/${req.file.key}`;
      }

      // 5. อัปเดตข้อมูลในฐานข้อมูลด้วยข้อมูลใหม่ทั้งหมด
      await connection.query(
        "UPDATE Category SET category_name = ?, category_name_en = ?, icon_url = ? WHERE category_id = ?",
        [category_name, category_name_en, newIconUrl, id]
      );

      // 6. ยืนยันการเปลี่ยนแปลงทั้งหมดในฐานข้อมูล
      await connection.commit();

      // 7. (สำคัญ) หลังจากบันทึก DB สำเร็จแล้ว ค่อยลบไฟล์เก่าทิ้ง
      // เงื่อนไข: ต้องมีการอัปโหลดไฟล์ใหม่ (req.file) และมีไฟล์เก่าอยู่ (oldIconUrl)
      if (req.file && oldIconUrl) {
        await deleteFileFromR2(oldIconUrl);
      }

      res.status(200).json({ message: "Category updated successfully" });
    } catch (error) {
      // หากเกิดข้อผิดพลาด ให้ย้อนกลับการเปลี่ยนแปลงทั้งหมด
      await connection.rollback();
      console.error("Update Category Error:", error);
      res.status(500).json({ message: "Error updating category" });
    } finally {
      // คืน Connection กลับสู่ Pool ไม่ว่าจะสำเร็จหรือล้มเหลว
      connection.release();
    }
  }
);

// DELETE: ลบประเภทสินค้า (Admin Only)
app.delete(
  "/api/admin/categories/:id",
  [authenticateToken, authorizeAdmin],
  async (req, res) => {
    const { id } = req.params;
    const connection = await db.getConnection();

    try {
      await connection.beginTransaction();

      // 1. ดึง URL ของไอคอนมาก่อน
      const [category] = await connection.query(
        "SELECT icon_url FROM Category WHERE category_id = ?",
        [id]
      );
      const iconUrlToDelete = category.length > 0 ? category[0].icon_url : null;

      // 2. (สำคัญ) พยายามลบข้อมูลจากฐานข้อมูล "ก่อน"
      const [deleteResult] = await connection.query(
        "DELETE FROM Category WHERE category_id = ?",
        [id]
      );

      // ถ้าลบไม่สำเร็จ (เพราะมีสินค้าผูกอยู่) จะเกิด error และโค้ดจะข้ามไปที่ catch ทันที

      await connection.commit(); // ยืนยันการลบข้อมูลใน DB

      // 3. ถ้าการลบข้อมูลสำเร็จ และมี URL ของไอคอนอยู่ ค่อยสั่งลบไฟล์
      if (iconUrlToDelete) {
        await deleteFileFromR2(iconUrlToDelete);
      }

      res.status(200).json({ message: "Category deleted successfully" });
    } catch (error) {
      await connection.rollback(); // ย้อนกลับการแก้ไขถ้าเกิดปัญหา

      if (error.code === "ER_ROW_IS_REFERENCED_2") {
        return res.status(400).json({
          message: "ไม่สามารถลบได้ เนื่องจากมีสินค้าใช้ประเภทนี้อยู่",
        });
      }
      res.status(500).json({ message: "Error deleting category" });
    } finally {
      connection.release();
    }
  }
);

// GET: ค้นหาลูกค้าสำหรับระบบ POS
app.get(
  "/api/admin/users/search",
  [authenticateToken, authorizeAdmin],
  async (req, res) => {
    const { q } = req.query;
    if (!q || q.length < 2) {
      return res.json([]);
    }

    try {
      const searchTerm = `%${q}%`;
      const sql =
        "SELECT user_id, username, email, phone, points FROM Users WHERE role_id = 1 AND (username LIKE ? OR email LIKE ? OR phone LIKE ?)";
      const [users] = await db.query(sql, [searchTerm, searchTerm, searchTerm]);
      res.json(users);
    } catch (error) {
      console.error("Search users error:", error);
      res.status(500).json({ message: "Error searching for users" });
    }
  }
);

// POST: สร้างออเดอร์หน้าร้าน (POS)
app.post(
  "/api/admin/orders/create-in-store",
  [authenticateToken, authorizeAdmin],
  async (req, res) => {
    const { items, totalPrice, userId, cashReceived, changeGiven } = req.body;
    const employeeId = req.user.userId; // ID ของพนักงานที่ทำรายการ

    if (!items || items.length === 0 || !totalPrice) {
      return res.status(400).json({ message: "ข้อมูลออเดอร์ไม่ครบถ้วน" });
    }

    const connection = await db.getConnection();
    try {
      await connection.beginTransaction();

      const customerId = userId || null; // ถ้าไม่มีลูกค้า ให้เป็น NULL

      const shippingInfo = {
        name: customerId ? `Customer ID: ${customerId}` : "Walk-in Customer",
        phone: "",
        address: "In-store purchase",
      };

      // --- จุดที่แก้ไข ---
      // 1. เพิ่ม `subtotal` เข้าไปในคำสั่ง INSERT
      // 2. เพิ่ม `totalPrice` เข้าไปใน list ของค่าที่จะใส่ (สำหรับ subtotal)
      const orderSql = `
            INSERT INTO Orders (user_id, subtotal, shipping_name, shipping_phone, shipping_address, total_price, status, payment_method, pay_date, order_date, cash_received, change_given) 
            VALUES (?, ?, ?, ?, ?, ?, 'completed', 'in_store', NOW(), NOW(), ?, ?)
        `;
      const [orderResult] = await connection.query(orderSql, [
        customerId,
        totalPrice, // <--- เพิ่มค่านี้สำหรับ subtotal
        shippingInfo.name,
        shippingInfo.phone,
        shippingInfo.address,
        totalPrice,
        cashReceived,
        changeGiven,
      ]);
      const newOrderId = orderResult.insertId;

      // (โค้ดส่วนที่เหลือเหมือนเดิม)
      const orderItemsSql =
        "INSERT INTO Order_items (order_id, product_id, quantity, current_price, selected_options) VALUES ?";
      const orderItemsValues = items.map((item) => [
        newOrderId,
        item.product_id,
        item.quantity,
        item.price,
        item.selected_options ? JSON.stringify(item.selected_options) : null,
      ]);
      await connection.query(orderItemsSql, [orderItemsValues]);

      if (customerId && totalPrice > 0) {
        const pointsToAdd = Math.floor(totalPrice / 10);

        if (pointsToAdd > 0) {
          await connection.query(
            "UPDATE Users SET points = points + ? WHERE user_id = ?",
            [pointsToAdd, customerId]
          );

          await connection.query(
            "INSERT INTO PointHistory (user_id, order_id, points_change, transaction_type, description) VALUES (?, ?, ?, ?, ?)",
            [
              customerId,
              newOrderId,
              pointsToAdd,
              "earn",
              `ได้รับแต้มจากออเดอร์ #${newOrderId}`,
            ]
          );
        }
      }

      await connection.commit();
      res.status(201).json({
        message: `สร้างออเดอร์หน้าร้าน #${newOrderId} สำเร็จ`,
        orderId: newOrderId,
      });
    } catch (error) {
      await connection.rollback();
      console.error("Create In-Store Order Error:", error);
      res.status(500).json({ message: "Failed to create in-store order" });
    } finally {
      connection.release();
    }
  }
);

// --- Store Information APIs ---

const storeUploads = uploadR2.fields([
  { name: "image", maxCount: 1 },
  { name: "qr_code_file", maxCount: 1 },
]);

// GET: ดึงข้อมูลร้านค้า
app.get("/api/store-info", async (req, res) => {
  try {
    const [rows] = await db.query(
      "SELECT id, name, name_en, address, address_en, phone, email, image_url, map_url, facebook_url, youtube_url, qr_code_url, bank_name, account_name, account_number FROM StoreInfo WHERE id = 1"
    );
    if (rows.length === 0) {
      return res.json(null);
    }
    res.json(rows[0]);
  } catch (error) {
    res.status(500).json({ message: "Error fetching store information" });
  }
});

// PUT: อัปเดตข้อมูลร้านค้า
app.put(
  "/api/store-info",
  [authenticateToken, authorizeAdmin, storeUploads],
  async (req, res) => {
    const {
      name,
      name_en,
      address,
      address_en,
      phone,
      email,
      map_url,
      facebook_url,
      youtube_url,
      existing_image_url,
      existing_qr_code_url,
      // [เพิ่ม] รับข้อมูลบัญชีจากฟอร์ม
      bank_name,
      account_name,
      account_number,
    } = req.body;

    let imageUrl = existing_image_url || null;
    if (req.files && req.files.image) {
      imageUrl = `${process.env.R2_PUBLIC_URL}/${req.files.image[0].key}`;
      if (existing_image_url) {
        await deleteFileFromR2(existing_image_url);
      }
    }

    let qrCodeUrl = existing_qr_code_url || null;
    if (req.files && req.files.qr_code_file) {
      qrCodeUrl = `${process.env.R2_PUBLIC_URL}/${req.files.qr_code_file[0].key}`;
      if (existing_qr_code_url) {
        await deleteFileFromR2(existing_qr_code_url);
      }
    }

    try {
      const [rows] = await db.query("SELECT id FROM StoreInfo WHERE id = 1");
      if (rows.length > 0) {
        // [แก้ไข] เพิ่ม field บัญชีในคำสั่ง UPDATE
        const sql = `
          UPDATE StoreInfo SET 
            name = ?, name_en = ?, address = ?, address_en = ?, phone = ?, email = ?, 
            image_url = ?, map_url = ?, facebook_url = ?, youtube_url = ?, qr_code_url = ?,
            bank_name = ?, account_name = ?, account_number = ?
          WHERE id = 1
        `;
        await db.query(sql, [
          name,
          name_en,
          address,
          address_en,
          phone,
          email,
          imageUrl,
          map_url,
          facebook_url,
          youtube_url,
          qrCodeUrl,
          bank_name,
          account_name,
          account_number,
        ]);
      } else {
        // [แก้ไข] เพิ่ม field บัญชีในคำสั่ง INSERT
        const sql = `
          INSERT INTO StoreInfo (id, name, name_en, address, address_en, phone, email, image_url, map_url, facebook_url, youtube_url, qr_code_url, bank_name, account_name, account_number)
          VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `;
        await db.query(sql, [
          name,
          name_en,
          address,
          address_en,
          phone,
          email,
          imageUrl,
          map_url,
          facebook_url,
          youtube_url,
          qrCodeUrl,
          bank_name,
          account_name,
          account_number,
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

// GET: ดึงประวัติแต้มของลูกค้าที่ล็อกอินอยู่
app.get("/api/user/points-history", authenticateToken, async (req, res) => {
  const userId = req.user.userId;

  try {
    const sql =
      "SELECT * FROM PointHistory WHERE user_id = ? ORDER BY transaction_date DESC";
    const [history] = await db.query(sql, [userId]);
    res.status(200).json(history);
  } catch (error) {
    console.error("Get Points History Error:", error);
    res
      .status(500)
      .json({ message: "เกิดข้อผิดพลาดในการดึงข้อมูลประวัติแต้ม" });
  }
});

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
