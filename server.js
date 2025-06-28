require("dotenv").config();
const express = require("express");
const mysql = require("mysql2");
const bcrypt = require("bcryptjs");
const cors = require("cors");
const jwt = require("jsonwebtoken"); // 1. NEW: นำเข้า jsonwebtoken

const app = express();
app.use(cors());
app.use(express.json());

const db = mysql
  .createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_DATABASE,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
  })
  .promise();

// --- API Endpoint สำหรับการลงทะเบียน (ไม่มีการเปลี่ยนแปลง) ---
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

// --- API Endpoint สำหรับการล็อกอิน (UPDATED: เพิ่มการสร้าง JWT) ---
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

    // 2. UPDATED: สร้าง JWT Token
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
      token: token, // ส่ง token กลับไป
      user: userInfo,
    });
  } catch (error) {
    console.error("Database Error:", error);
    return res.status(500).json({ message: "เกิดข้อผิดพลาดในเซิร์ฟเวอร์" });
  }
});

// 3. NEW: สร้าง Middleware สำหรับตรวจสอบ Token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1]; // Bearer TOKEN

  if (token == null) return res.sendStatus(401); // Unauthorized

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403); // Forbidden
    req.user = user;
    next();
  });
};

// --- API Endpoint สำหรับดึงข้อมูลสินค้าทั้งหมด (ยังเป็น Public) ---
app.get("/api/products", async (req, res) => {
  try {
    const sql = "SELECT * FROM Product WHERE sales_status = 1";
    const [products] = await db.query(sql);
    res.status(200).json(products);
  } catch (error) {
    console.error("Database Error:", error);
    res.status(500).json({ message: "เกิดข้อผิดพลาดในการดึงข้อมูลสินค้า" });
  }
});

// NEW: GET ดึงข้อมูลสินค้าชิ้นเดียวตาม ID
app.get("/api/product/:id", async (req, res) => {
  const { id } = req.params; // ดึง id มาจาก URL parameter

  try {
    const sql = "SELECT * FROM Product WHERE product_id = ?";
    const [products] = await db.query(sql, [id]);

    if (products.length === 0) {
      return res.status(404).json({ message: "ไม่พบสินค้าชิ้นนี้" });
    }

    res.status(200).json(products[0]); // ส่งข้อมูลสินค้าตัวแรกที่เจอ (ซึ่งควรจะมีแค่ตัวเดียว)
  } catch (error) {
    console.error("Get Single Product Error:", error);
    res.status(500).json({ message: "เกิดข้อผิดพลาดในการดึงข้อมูลสินค้า" });
  }
});

// 4. NEW: สร้าง Endpoint สำหรับเพิ่มสินค้าลงตะกร้า (Protected Route)
// API Endpoint สำหรับเพิ่มสินค้าลงตะกร้า (Protected Route พร้อม Logic ฐานข้อมูล)
app.post("/api/cart/add", authenticateToken, async (req, res) => {
  // 1. ดึงข้อมูลจาก request body และ token
  const { productId, quantity } = req.body;
  const userId = req.user.userId;

  if (!productId || !quantity) {
    return res.status(400).json({ message: "ข้อมูลไม่ครบถ้วน" });
  }

  try {
    const connection = await db.getConnection(); // ใช้ connection เพื่อทำ transaction

    // 2. ตรวจสอบว่ามีสินค้านี้ในตะกร้าของผู้ใช้อยู่แล้วหรือไม่
    const checkSql =
      "SELECT * FROM CartItem WHERE user_id = ? AND product_id = ?"; //
    const [existingItems] = await connection.query(checkSql, [
      userId,
      productId,
    ]);

    if (existingItems.length > 0) {
      // 3. ถ้ามีอยู่แล้ว ให้อัปเดตจำนวนสินค้า (quantity)
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
      // 4. ถ้ายังไม่มี ให้เพิ่มเป็นรายการใหม่ในตะกร้า
      const insertSql =
        "INSERT INTO CartItem (user_id, product_id, quantity) VALUES (?, ?, ?)"; //
      await connection.query(insertSql, [userId, productId, quantity]);
      res.status(201).json({ message: `เพิ่มสินค้าลงตะกร้าสำเร็จ!` });
    }

    connection.release(); // คืน connection กลับสู่ pool
  } catch (error) {
    // 5. จัดการ Error
    console.error("Cart Add Error:", error);
    res.status(500).json({ message: "เกิดข้อผิดพลาดในการเพิ่มสินค้าลงตะกร้า" });
  }
});

// --- API Endpoints สำหรับจัดการตะกร้าสินค้า ---

// GET: ดึงข้อมูลสินค้าทั้งหมดในตะกร้าของผู้ใช้
app.get("/api/cart", authenticateToken, async (req, res) => {
  const userId = req.user.userId;

  try {
    // เราต้อง JOIN ตาราง CartItem กับ Product เพื่อเอาข้อมูลสินค้า (ชื่อ, ราคา, รูปภาพ) มาด้วย
    const sql = `
            SELECT 
                ci.cart_item_id, 
                ci.quantity, 
                p.product_id,
                p.name,
                p.price,
                p.image_url
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

// PUT: อัปเดตจำนวนสินค้าในตะกร้า
app.put("/api/cart/update/:cartItemId", authenticateToken, async (req, res) => {
  const { quantity } = req.body;
  const { cartItemId } = req.params;
  const userId = req.user.userId;

  // ตรวจสอบว่าจำนวนสินค้า hợp lệ
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

// DELETE: ลบสินค้าออกจากตะกร้า
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

    // 1. UPDATED: แก้ไข SQL ให้ค้นหาจาก 'name' เพียงอย่างเดียว
    const sql = "SELECT * FROM Product WHERE name LIKE ?";

    // 2. UPDATED: แก้ไข Parameters ให้เหลือแค่ตัวเดียวให้ตรงกับ '?' ใน SQL
    const [products] = await db.query(sql, [searchQuery]);

    res.status(200).json(products);
  } catch (error) {
    console.error("Search Product Error:", error);
    res.status(500).json({ message: "เกิดข้อผิดพลาดในการค้นหาสินค้า" });
  }
});

const PORT = process.env.API_PORT || 3001;
app.listen(PORT, () => {
  console.log(`Backend API server is running at http://localhost:${PORT}`);
});
