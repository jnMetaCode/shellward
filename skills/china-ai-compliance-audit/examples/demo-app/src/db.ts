import { createPool } from 'mysql2/promise'

// 只读账号：机器人只需要查客户资料
const pool = createPool({ host: process.env.DB_HOST, user: 'bot_readonly', database: 'crm' })

export async function findUser(id: string) {
  const [rows] = await pool.query('SELECT name, phone, idCard FROM customers WHERE id = ?', [id])
  return (rows as any[])[0]
}
