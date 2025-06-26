// backend/server.js

// 1. นำเข้า Library ที่จำเป็น
require("dotenv").config();
const express = require("express");
const mysql = require("mysql2");
const bcrypt = require("bcryptjs"); // UPDATED: นำ bcrypt กลับมาใช้เพื่อความปลอดภัย
const cors = require("cors");

// 2. ตั้งค่า Express App
const app = express();
app.use(cors());
app.use(express.json());

// 3. สร้าง Connection Pool ไปยัง MySQL
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

// --- API Endpoint สำหรับการลงทะเบียน (เวอร์ชันอัปเดตและปลอดภัย) ---
app.post("/api/register", async (req, res) => {
  // UPDATED: รับ phone และ address เพิ่ม
  const { username, email, password, phone, address } = req.body;

  // ตรวจสอบข้อมูลที่จำเป็น
  if (!username || !email || !password) {
    return res
      .status(400)
      .json({ message: "กรุณากรอกชื่อผู้ใช้, อีเมล และรหัสผ่าน" });
  }

  try {
    // เข้ารหัสผ่านก่อนบันทึก
    const hashedPassword = await bcrypt.hash(password, 10);

    // UPDATED: เพิ่ม phone และ address ลงในคำสั่ง SQL
    const sql =
      "INSERT INTO Users (username, email, password, role_id, phone, address) VALUES (?, ?, ?, ?, ?, ?)";

    // role_id: 1 คือ customer, phone และ address อาจเป็น null ได้ถ้าผู้ใช้ไม่กรอก
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

// --- API Endpoint สำหรับการล็อกอิน (เวอร์ชันปลอดภัย) ---
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

    // เปรียบเทียบรหัสผ่านที่เข้ารหัสแล้ว
    const isPasswordMatch = await bcrypt.compare(password, user.password);

    if (!isPasswordMatch) {
      return res
        .status(401)
        .json({ message: "ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง" });
    }

    const userInfo = {
      userId: user.user_id,
      username: user.username,
      email: user.email,
      role: user.role_name,
      points: user.points,
    };

    res.status(200).json({ message: "ล็อกอินสำเร็จ!", user: userInfo });
  } catch (error) {
    console.error("Database Error:", error);
    return res.status(500).json({ message: "เกิดข้อผิดพลาดในเซิร์ฟเวอร์" });
  }
});

// 4. รันเซิร์ฟเวอร์
const PORT = process.env.API_PORT || 3001;
app.listen(PORT, () => {
  console.log(`Backend API server is running at http://localhost:${PORT}`);
});

// --- API Endpoint สำหรับดึงข้อมูลสินค้าทั้งหมด ---
app.get("/api/products", async (req, res) => {
  try {
    const sql = "SELECT * FROM Product WHERE sales_status = 1"; // ดึงเฉพาะสินค้าที่มีสถานะพร้อมขาย
    const [products] = await db.query(sql);
    res.status(200).json(products);
  } catch (error) {
    console.error("Database Error:", error);
    res.status(500).json({ message: "เกิดข้อผิดพลาดในการดึงข้อมูลสินค้า" });
  }
});
