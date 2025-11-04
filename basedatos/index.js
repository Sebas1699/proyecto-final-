import express from "express";
import cors from "cors"; // 1. Importamos CORS
import conexion from "./db.js"; // Importamos la conexión que ya creaste
import path from "path"; // Módulo para trabajar con rutas de archivos
import { fileURLToPath } from "url"; // Módulo para obtener la ruta del archivo actual
import bcrypt from "bcrypt"; // Importamos bcrypt para hashear contraseñas
import jwt from "jsonwebtoken"; // Importamos JWT para las sesiones
import dotenv from "dotenv"; // Importamos dotenv

dotenv.config(); // Cargamos las variables de entorno del archivo .env


const app = express();
const port = 3000;

// --- Middlewares ---
// 2. Habilitamos CORS para permitir peticiones desde tu frontend
app.use(cors());
// 3. Habilitamos el parseo de JSON para poder leer los datos de los formularios (ej: registro)
app.use(express.json());

// --- Configuración para servir archivos estáticos (HTML, CSS) ---
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
// Le decimos a Express que la carpeta 'principal' contiene archivos públicos
app.use(express.static(path.join(__dirname, '../principal')));
// Le decimos a Express que la carpeta 'roll' también contiene archivos públicos
app.use('/roll', express.static(path.join(__dirname, '../roll')));

// --- Middleware de Autenticación ---
const verifyToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Formato: "Bearer TOKEN"

  if (token == null) {
    return res.sendStatus(401); // Unauthorized: no hay token
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.sendStatus(403); // Forbidden: el token no es válido
    }
    // Guardamos los datos del usuario del token en el objeto `req` para usarlo en rutas posteriores
    req.user = user;
    next(); // El token es válido, continuamos
  });
};

// --- Middleware de Autorización (Admin) ---
const verifyAdmin = (req, res, next) => {
  if (req.user.role !== 'administrador' && req.user.role !== 'superusuario') {
    return res.status(403).json({ message: "Acceso denegado. Se requiere rol de administrador." });
  }
  next();
};

// --- Middleware de Autorización (Superusuario) ---
const verifySuperuser = (req, res, next) => {
  if (req.user.role !== 'superusuario') {
    return res.status(403).json({ message: "Acceso denegado. Se requiere rol de superusuario." });
  }
  next();
};


// --- Rutas de la API ---

// Ruta para obtener todos los usuarios
app.get("/api/usuarios", async (req, res) => {
  try {
    // Usamos el pool de conexiones con async/await para un código más limpio
    const [resultados] = await conexion.query("SELECT * FROM usuarios");
    res.json(resultados);
  } catch (error) {
    console.error("Error al consultar los usuarios:", error);
    res.status(500).json({ error: "Error en el servidor al obtener usuarios" });
  }
});

// Ruta para registrar un nuevo usuario (POST)
app.post("/api/register", async (req, res) => {
  const { nombres, apellidos, cedula, email, password } = req.body;

  // 1. Validación básica de que los datos llegaron
  if (!nombres || !apellidos || !cedula || !email || !password) {
    return res.status(400).json({ message: "Todos los campos son obligatorios." });
  }

  try {
    // 2. Verificar si el correo electrónico ya existe
    const [existingUser] = await conexion.query("SELECT correo FROM usuarios WHERE correo = ?", [email]);
    if (existingUser.length > 0) {
      return res.status(409).json({ message: "El correo electrónico ya está registrado." }); // 409 Conflict
    }

    // 3. Hashear la contraseña antes de guardarla
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // 4. Definimos el rol por defecto. '3' corresponde a 'usuario' en tu tabla de roles.
    const defaultRoleId = 3;

    // 4. Insertar el nuevo usuario en la base de datos
    const [result] = await conexion.query(
      "INSERT INTO usuarios (nombres, apellidos, cedula, correo, contraseña, id_rol) VALUES (?, ?, ?, ?, ?, ?)",
      [nombres, apellidos, cedula, email, hashedPassword, defaultRoleId]
    );

    // ¡Mejora! Agregamos un log para confirmar en la terminal.
    console.log(`✅ Usuario registrado con éxito. ID: ${result.insertId}`);

    // 5. Enviar una respuesta de éxito
    res.status(201).json({ message: "Usuario registrado con éxito", userId: result.insertId });
  } catch (error) {
    console.error("Error en el registro de usuario:", error);
    res.status(500).json({ message: "Error en el servidor al registrar el usuario." });
  }
});

// Ruta para iniciar sesión (POST)
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;

  // 1. Validación de que los datos llegaron
  if (!email || !password) {
    return res.status(400).json({ message: "Correo y contraseña son obligatorios." });
  }

  try {
    // 2. Buscar al usuario y obtener su contraseña hasheada y su rol
    const [users] = await conexion.query(
      `SELECT u.id_usuario, u.nombres, u.contraseña, r.nombre_rol 
       FROM usuarios u 
       JOIN roles r ON u.id_rol = r.id_rol 
       WHERE u.correo = ?`,
      [email]
    );

    // 3. Si no se encuentra el usuario
    if (users.length === 0) {
      return res.status(404).json({ message: "Credenciales inválidas." }); // Usamos un mensaje genérico por seguridad
    }

    const user = users[0];

    // 4. Comparar la contraseña enviada con la hasheada en la BD
    const isPasswordCorrect = await bcrypt.compare(password, user.contraseña);
    if (!isPasswordCorrect) {
      return res.status(401).json({ message: "Credenciales inválidas." }); // 401 Unauthorized
    }

    // 5. Si todo es correcto, creamos un token JWT
    const payload = {
      userId: user.id_usuario,
      role: user.nombre_rol
    };

    // Es MUY importante que esta clave secreta sea compleja y esté en una variable de entorno en un proyecto real
    const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1h' }); // El token expira en 1 hora

    // 6. Enviamos el token al cliente
    res.status(200).json({ message: `Bienvenido, ${user.nombres}!`, token: token, role: user.nombre_rol, name: user.nombres });
  } catch (error) {
    console.error("Error en el inicio de sesión:", error);
    res.status(500).json({ message: "Error en el servidor al intentar iniciar sesión." });
  }
});

// Ruta para crear o actualizar una hoja de vida (protegida por token)
app.post("/api/cv", verifyToken, async (req, res) => {
  // Obtenemos el id del usuario desde el token que el middleware `verifyToken` ya validó
  const userId = req.user.userId;

  const {
    perfil_profesional,
    experiencia,
    educacion,
    habilidades,
    idiomas,
    referencias,
    cargo_aplicar,
    foto_perfil
  } = req.body;

  try {
    // Usamos INSERT ... ON DUPLICATE KEY UPDATE para crear o actualizar la hoja de vida.
    // Esto asume que `id_usuario` en `hoja_vida` es una clave ÚNICA.
    const sql = `
      INSERT INTO hoja_vida (id_usuario, perfil_profesional, experiencia, educacion, habilidades, idiomas, referencias, cargo_aplicar, foto_perfil)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON DUPLICATE KEY UPDATE
      perfil_profesional = VALUES(perfil_profesional), experiencia = VALUES(experiencia), educacion = VALUES(educacion), habilidades = VALUES(habilidades), idiomas = VALUES(idiomas), referencias = VALUES(referencias), cargo_aplicar = VALUES(cargo_aplicar), foto_perfil = VALUES(foto_perfil)
    `;
    await conexion.query(sql, [userId, perfil_profesional, experiencia, educacion, habilidades, idiomas, referencias, cargo_aplicar, foto_perfil]);
    res.status(200).json({ message: "Hoja de vida guardada con éxito." });
  } catch (error) {
    console.error("Error al guardar la hoja de vida:", error);
    res.status(500).json({ message: "Error en el servidor al guardar la hoja de vida." });
  }
});

// Ruta para OBTENER la hoja de vida de un usuario (protegida por token)
app.get("/api/cv", verifyToken, async (req, res) => {
  const userId = req.user.userId;

  try {
    // Unimos las tablas usuarios y hoja_vida para obtener toda la información
    const [userData] = await conexion.query(
      `SELECT u.nombres, u.apellidos, u.cedula, hv.*
       FROM usuarios u
       LEFT JOIN hoja_vida hv ON u.id_usuario = hv.id_usuario
       WHERE u.id_usuario = ?`,
      [userId]
    );

    if (userData.length > 0) {
      // Si se encuentra la hoja de vida, se envía
      res.status(200).json(userData[0]);
    } else {
      // Esto no debería pasar si el token es válido, pero por seguridad
      res.status(200).json({});
    }
  } catch (error) {
    console.error("Error al obtener la hoja de vida:", error);
    res.status(500).json({ message: "Error en el servidor al obtener la hoja de vida." });
  }
});

// Ruta principal que sirve tu página de bienvenida
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '../principal', 'pageP.html'));
});

// Ruta para servir la página de registro
app.get('/register.html', (req, res) => {
  res.sendFile(path.join(__dirname, '../principal', 'register.html'));
});

// Ruta para servir la página de inicio de sesión (a futuro)
app.get('/login.html', (req, res) => {
  res.sendFile(path.join(__dirname, '../principal', 'login.html'));
});

// Ruta para servir la página del dashboard del usuario
app.get('/roll/usuario/dashboard.html', (req, res) => {
  res.sendFile(path.join(__dirname, '../roll/usuario', 'dashboard.html'));
});

// Ruta para servir el panel del administrador
app.get('/roll/admin/panel.html', (req, res) => {
  res.sendFile(path.join(__dirname, '../roll/admin', 'panel.html'));
});

// Ruta para servir el panel del superusuario
app.get('/roll/super/panel.html', (req, res) => {
  res.sendFile(path.join(__dirname, '../roll/super', 'panel.html'));
});

// --- Rutas de API para Administrador ---

// Ruta para obtener la lista de usuarios con hoja de vida
app.get("/api/admin/cv-list", [verifyToken, verifyAdmin], async (req, res) => {
  try {
    const [cvList] = await conexion.query(`
      SELECT u.id_usuario, u.nombres, u.apellidos, hv.cargo_aplicar, hv.estado
      FROM usuarios u
      JOIN hoja_vida hv ON u.id_usuario = hv.id_usuario
      ORDER BY u.apellidos, u.nombres;
    `);
    res.status(200).json(cvList);
  } catch (error) {
    console.error("Error al obtener la lista de hojas de vida:", error);
    res.status(500).json({ message: "Error en el servidor." });
  }
});

// Ruta para actualizar el estado de una hoja de vida
app.post("/api/admin/cv-status", [verifyToken, verifyAdmin], async (req, res) => {
  const { userId, status } = req.body;

  // Validación
  if (!userId || !['aceptado', 'rechazado'].includes(status)) {
    return res.status(400).json({ message: "Datos inválidos." });
  }

  try {
    await conexion.query("UPDATE hoja_vida SET estado = ? WHERE id_usuario = ?", [status, userId]);
    res.status(200).json({ message: `Hoja de vida actualizada a '${status}'.` });
  } catch (error) {
    console.error("Error al actualizar el estado de la hoja de vida:", error);
    res.status(500).json({ message: "Error en el servidor." });
  }
});

// Ruta para que un admin vea una hoja de vida específica
app.get("/api/admin/cv/:userId", [verifyToken, verifyAdmin], async (req, res) => {
  const { userId } = req.params;

  try {
    const [cvData] = await conexion.query(
      `SELECT u.nombres, u.apellidos, u.cedula, u.correo, hv.*
       FROM usuarios u
       LEFT JOIN hoja_vida hv ON u.id_usuario = hv.id_usuario
       WHERE u.id_usuario = ?`,
      [userId]
    );

    if (cvData.length === 0) {
      return res.status(404).json({ message: "Usuario no encontrado." });
    }

    if (!cvData[0].id_hoja) {
      return res.status(404).json({ message: "Este usuario no ha creado una hoja de vida." });
    }

    res.status(200).json(cvData[0]);
  } catch (error) {
    console.error("Error al obtener la hoja de vida para el admin:", error);
    res.status(500).json({ message: "Error en el servidor." });
  }
});

// --- Rutas de API para Superusuario ---

// Ruta para crear un nuevo usuario
app.post("/api/super/create-user", [verifyToken, verifySuperuser], async (req, res) => {
  const { nombres, apellidos, cedula, correo, contraseña, id_rol } = req.body;

  if (!nombres || !apellidos || !cedula || !correo || !contraseña || !id_rol) {
    return res.status(400).json({ message: "Todos los campos son obligatorios." });
  }

  try {
    const hashedPassword = await bcrypt.hash(contraseña, 10);
    await conexion.query(
      "INSERT INTO usuarios (nombres, apellidos, cedula, correo, contraseña, id_rol) VALUES (?, ?, ?, ?, ?, ?)",
      [nombres, apellidos, cedula, correo, hashedPassword, id_rol]
    );
    res.status(201).json({ message: "Usuario creado con éxito." });
  } catch (error) {
    if (error.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({ message: "El correo o la cédula ya están registrados." });
    }
    console.error("Error al crear usuario:", error);
    res.status(500).json({ message: "Error en el servidor." });
  }
});

// Ruta para obtener la lista de administradores
app.get("/api/super/admins", [verifyToken, verifySuperuser], async (req, res) => {
  try {
    const [admins] = await conexion.query(
      "SELECT id_usuario, nombres, apellidos, correo FROM usuarios WHERE id_rol = 2"
    );
    res.status(200).json(admins);
  } catch (error) {
    console.error("Error al obtener administradores:", error);
    res.status(500).json({ message: "Error en el servidor." });
  }
});

// Ruta para eliminar un usuario
app.delete("/api/super/user/:userId", [verifyToken, verifySuperuser], async (req, res) => {
  const { userId } = req.params;
  try {
    // Opcional: No permitir que un superusuario se elimine a sí mismo
    if (req.user.userId == userId) {
      return res.status(403).json({ message: "No puedes eliminar tu propia cuenta." });
    }
    await conexion.query("DELETE FROM usuarios WHERE id_usuario = ?", [userId]);
    res.status(200).json({ message: "Usuario eliminado con éxito." });
  } catch (error) {
    console.error("Error al eliminar usuario:", error);
    res.status(500).json({ message: "Error en el servidor." });
  }
});

// Ruta para obtener todos los usuarios y su estado de postulación
app.get("/api/super/all-users", [verifyToken, verifySuperuser], async (req, res) => {
  try {
    const [users] = await conexion.query(`
      SELECT u.nombres, u.apellidos, r.nombre_rol, hv.cargo_aplicar, hv.estado
      FROM usuarios u
      JOIN roles r ON u.id_rol = r.id_rol
      LEFT JOIN hoja_vida hv ON u.id_usuario = hv.id_usuario
      WHERE u.id_rol = 3
      ORDER BY u.id_usuario
    `);
    res.status(200).json(users);
  } catch (error) {
    console.error("Error al obtener todos los usuarios:", error);
    res.status(500).json({ message: "Error en el servidor." });
  }
});


app.listen(port, () => {
  console.log(`🚀 Servidor escuchando en http://localhost:${port}`);
});
