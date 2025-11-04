import mysql from "mysql2/promise";

const pool = mysql.createPool({
  host: "localhost",
  user: "root",         
  password: "Sebas1699", 
  database: "hoja_vida_db",  
  waitForConnections: true,
  connectionLimit: 10, // Número máximo de conexiones en el pool
  queueLimit: 0
});

try {
  await pool.query('SELECT 1');
  console.log("✅ Conexión exitosa a la base de datos MySQL");
} catch (error) {
  console.error("❌ Error al conectar con la base de datos:", error);
}

export default pool;
