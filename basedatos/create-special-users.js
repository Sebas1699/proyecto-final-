import bcrypt from 'bcrypt';
import pool from './db.js'; // Reutilizamos tu pool de conexiones

async function createSpecialUsers() {
  console.log('Iniciando creación de usuarios especiales...');

  const saltRounds = 10;

  // --- Datos del Superusuario ---
  const superUser = {
    nombres: 'Sebastian',
    apellidos: 'Gómez Ruiz',
    cedula: '1000123456',
    correo: 'super@empresa.com',
    contraseñaPlana: 'super123', // Contraseña en texto plano
    id_rol: 1
  };

  // --- Datos del Administrador ---
  const adminUser = {
    nombres: 'Laura',
    apellidos: 'Martínez López',
    cedula: '2000456789',
    correo: 'admin@empresa.com',
    contraseñaPlana: 'admin123', // Contraseña en texto plano
    id_rol: 2
  };

  try {
    // Hashear y crear Superusuario
    const hashedSuperPassword = await bcrypt.hash(superUser.contraseñaPlana, saltRounds);
    await pool.query(
      "INSERT IGNORE INTO usuarios (nombres, apellidos, cedula, correo, contraseña, id_rol) VALUES (?, ?, ?, ?, ?, ?)",
      [superUser.nombres, superUser.apellidos, superUser.cedula, superUser.correo, hashedSuperPassword, superUser.id_rol]
    );
    console.log(`✅ Superusuario '${superUser.correo}' creado con éxito.`);

    // Hashear y crear Administrador
    const hashedAdminPassword = await bcrypt.hash(adminUser.contraseñaPlana, saltRounds);
    await pool.query(
      "INSERT IGNORE INTO usuarios (nombres, apellidos, cedula, correo, contraseña, id_rol) VALUES (?, ?, ?, ?, ?, ?)",
      [adminUser.nombres, adminUser.apellidos, adminUser.cedula, adminUser.correo, hashedAdminPassword, adminUser.id_rol]
    );
    console.log(`✅ Administrador '${adminUser.correo}' creado con éxito.`);

  } catch (error) {
    console.error('❌ Error al crear usuarios especiales:', error.message);
  } finally {
    await pool.end(); // Cerramos la conexión a la base de datos
    console.log('Proceso finalizado.');
  }
}

createSpecialUsers();