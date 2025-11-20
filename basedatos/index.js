import express from "express";
import cors from "cors"; 
import conexion from "./db.js"; 
import path from "path"; 
import { fileURLToPath } from "url"; 
import bcrypt from "bcrypt"; 
import jwt from "jsonwebtoken"; 
import dotenv from "dotenv";
import multer from "multer";
import fs from "fs";

// Cargar variables de entorno desde el archivo .env
dotenv.config(); 

const app = express();
const port = 3000;

app.use(cors());
app.use(express.json());

// me sirve para manejar las subidas de archivos
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const uploadDir = path.join(__dirname, 'uploads');

// me crea la carpeta uploads si no existe
if (!fs.existsSync(uploadDir)){
    fs.mkdirSync(uploadDir);
}
// me maneja el añadir las imagenes
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, uploadDir); // Directorio donde se guardarán las imágenes
  },
  filename: function (req, file, cb) {
    
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
  }
});

const upload = multer({ storage: storage });
// son las rutas para enviar los archivos  html,css,js e imagenes
app.use(express.static(path.join(__dirname, '../principal')));
app.use('/roll', express.static(path.join(__dirname, '../roll')));
app.use('/uploads', express.static(uploadDir)); 

// verifica el token 
const verifyToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; 

  if (token == null) {
    return res.status(401).json({ message: "No se proporcionó token de autenticación." }); // mensaje de no hay token
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ message: "Token no válido o expirado." }); // token no es válido
    }

    req.user = user; 
    next(); // Pasa a la siguiente ruta ruta.
  });
};

// verifica el rol del usuario que esta entrando
const verifyRole = (allowedRoles) => {
  return (req, res, next) => {
    if (!req.user || !req.user.role) {
      return res.status(403).json({ message: "Acceso denegado. Rol no especificado en el token." });
    }
    const hasRole = allowedRoles.includes(req.user.role);
    if (!hasRole) {
      return res.status(403).json({ message: `Acceso denegado. Se requiere uno de los siguientes roles: ${allowedRoles.join(', ')}.` });
    }
    next();
  };
};

// obtener todos los usuarios
app.get("/api/usuarios", async (req, res) => {
  try {
   
    const [resultados] = await conexion.query("SELECT * FROM usuarios");
    res.json(resultados);
  } catch (error) {
    console.error("Error al consultar los usuarios:", error);
    res.status(500).json({ error: "Error en el servidor al obtener usuarios" });
  }
});

// registrar un nuevo usuario 
app.post("/api/register", async (req, res) => {
  const { nombres, apellidos, cedula, email, password } = req.body;

  // Validación de datos
  if (!nombres || !apellidos || !cedula || !email || !password) {
    return res.status(400).json({ message: "Todos los campos son obligatorios." });
  }

  try {
    // Verificacion del correo
    const [existingUser] = await conexion.query("SELECT correo FROM usuarios WHERE correo = ?", [email]);
    if (existingUser.length > 0) {
      return res.status(409).json({ message: "El correo electrónico ya está registrado." }); // 409 Conflict
    }

    // encrypta la contraseña antes de guardarla
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Definimos el rol del usuario
    const defaultRoleId = 3;

    // crea un nuevo usuario en la base de datos 
    const [result] = await conexion.query(
      "INSERT INTO usuarios (nombres, apellidos, cedula, correo, contraseña, id_rol) VALUES (?, ?, ?, ?, ?, ?)",
      [nombres, apellidos, cedula, email, hashedPassword, defaultRoleId]
    );

    // confirma la creación del usuario
    console.log(`✅ Usuario registrado con éxito. ID: ${result.insertId}`);

    // mensaje de exito
    res.status(201).json({ message: "Usuario registrado con éxito", userId: result.insertId });
  } catch (error) {
    console.error("Error en el registro de usuario:", error);
    res.status(500).json({ message: "Error en el servidor al registrar el usuario." });
  }
});

// ruta de inicio de sesión
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;

  // validacion de datos
  if (!email || !password) {
    return res.status(400).json({ message: "Correo y contraseña son obligatorios." });
  }

  try {
    // busca el usuario
    const [users] = await conexion.query(
      `SELECT u.id_usuario, u.nombres, u.contraseña, r.nombre_rol 
       FROM usuarios u 
       JOIN roles r ON u.id_rol = r.id_rol 
       WHERE u.correo = ?`,
      [email]
    );

    // mensaje de error de usuario 
    if (users.length === 0) {
      return res.status(404).json({ message: "Credenciales inválidas." }); 
    }

    const user = users[0];

    // Comparar la contraseña enviada con la encyptada en la BD
    const isPasswordCorrect = await bcrypt.compare(password, user.contraseña);
    if (!isPasswordCorrect) {
      return res.status(401).json({ message: "Credenciales inválidas." }); // 401 Unauthorized
    }

    //Si todo es correcto, creamos un token JWT
    const payload = {
      userId: user.id_usuario,
      role: user.nombre_rol
    };

    // me obliga a que la sesion dure 1 hora
    const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1h' }); 

    // Enviamos el token al cliente
    res.status(200).json({ message: `Bienvenido, ${user.nombres}!`, token: token, role: user.nombre_rol, name: user.nombres });
  } catch (error) {
    console.error("Error en el inicio de sesión:", error);
    res.status(500).json({ message: "Error en el servidor al intentar iniciar sesión." });
  }
});

// creo o acualizo la hoja de vida
app.post("/api/cv", [verifyToken, upload.single('foto_perfil_archivo')], async (req, res) => {
  const userId = req.user.userId;

  // Datos de la hoja de vida que muestranos en el formulario
  const {
    perfil_profesional,
    experiencia,
    educacion,
    habilidades,
    idiomas,
    referencias,
    cargo_aplicar,
  } = req.body;

  // guardamos la ruta de la foto de perfil
  const foto_perfil_path = req.file ? `/uploads/${path.basename(req.file.path)}` : req.body.foto_perfil_existente;

  try {
    // Usamos INSERT ... ON DUPLICATE KEY UPDATE para crear o actualizar
    const sql = `
      INSERT INTO hoja_vida (id_usuario, perfil_profesional, experiencia, educacion, habilidades, idiomas, referencias, cargo_aplicar, foto_perfil)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) 
      ON DUPLICATE KEY UPDATE
      perfil_profesional = VALUES(perfil_profesional), experiencia = VALUES(experiencia), educacion = VALUES(educacion), habilidades = VALUES(habilidades), idiomas = VALUES(idiomas), referencias = VALUES(referencias), cargo_aplicar = VALUES(cargo_aplicar), foto_perfil = VALUES(foto_perfil)
    `;
    await conexion.query(sql, [userId, perfil_profesional, experiencia, educacion, habilidades, idiomas, referencias, cargo_aplicar, foto_perfil_path]);
    res.status(200).json({ message: "Hoja de vida guardada con éxito." });
  } catch (error) {
    console.error("Error al guardar la hoja de vida:", error);
    res.status(500).json({ message: "Error en el servidor al guardar la hoja de vida." });
  }
});

// crea un token para obtener la hoja de vida del usuario
app.get("/api/cv", verifyToken, async (req, res) => {
  const userId = req.user.userId;

  try {
    //mostrar la hoja de vida del usuario
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
      // error si no hay hoja de vida
      res.status(200).json({});
    }
  } catch (error) {
    console.error("Error al obtener la hoja de vida:", error);
    res.status(500).json({ message: "Error en el servidor al obtener la hoja de vida." });
  }
});

// ruta página de bienvenida
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '../principal', 'pageP.html'));
});

// ruta página de registro
app.get('/register.html', (req, res) => {
  res.sendFile(path.join(__dirname, '../principal', 'register.html'));
});

// ruta página de inicio de sesión (a futuro)
app.get('/login.html', (req, res) => {
  res.sendFile(path.join(__dirname, '../principal', 'login.html'));
});

// ruta página del dashboard del usuario
app.get('/roll/usuario/dashboard.html', (req, res) => {
  res.sendFile(path.join(__dirname, '../roll/usuario', 'dashboard.html'));
});

// ruta panel del administrador
app.get('/roll/admin/panel.html', (req, res) => {
  res.sendFile(path.join(__dirname, '../roll/admin', 'panel.html'));
});

// ruta panel del superusuario
app.get('/roll/super/panel.html', (req, res) => {
  res.sendFile(path.join(__dirname, '../roll/super', 'panel.html'));
});

// rutas Administrador 

// llama a todos los usuarios y su hoja de vida
app.get("/api/admin/cv-list", [verifyToken, verifyRole(['administrador', 'superusuario'])], async (req, res) => {
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

// actualiza el estado de la hoja de vida
app.post("/api/admin/cv-status", [verifyToken, verifyRole(['administrador', 'superusuario'])], async (req, res) => {
  const { userId, status } = req.body;

  // Verificación de datos
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

// me permite ver una hoja de vida específica
app.get("/api/admin/cv/:userId", [verifyToken, verifyRole(['administrador', 'superusuario'])], async (req, res) => {
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

// vacantes y Postulaciones 
// area usuario y manejo de sus datos en las vacantes
// valida que solo el admin pueda crear vacantes
app.post("/api/admin/vacancies", [verifyToken, verifyRole(['administrador', 'superusuario'])], async (req, res) => {
  const { titulo, descripcion } = req.body;
  const adminId = req.user.userId;

  if (!titulo || !descripcion) {
    return res.status(400).json({ message: "El título y la descripción son obligatorios." });
  }

  try {
    await conexion.query(
      "INSERT INTO vacantes (titulo, descripcion, id_admin) VALUES (?, ?, ?)",
      [titulo, descripcion, adminId]
    );
    res.status(201).json({ message: "Vacante creada con éxito." });
  } catch (error) {
    console.error("Error al crear la vacante:", error);
    res.status(500).json({ message: "Error en el servidor al crear la vacante." });
  }
});

// muestra todas las vacantes disponibles al usuario
app.get("/api/vacancies", verifyToken, async (req, res) => {
  try {
    const [vacancies] = await conexion.query("SELECT id_vacante, titulo, descripcion FROM vacantes ORDER BY fecha_creacion DESC");
    res.status(200).json(vacancies);
  } catch (error) {
    console.error("Error al obtener las vacantes:", error);
    res.status(500).json({ message: "Error en el servidor." });
  }
});

// sirve para que el usuario se postule a una vacante
app.post("/api/vacancies/:id/apply", verifyToken, async (req, res) => {
  const { id: id_vacante } = req.params;
  const id_usuario = req.user.userId;

  try {
    // verifica si ese usuario tiene hoja de vida creada
    const [cv] = await conexion.query("SELECT id_hoja FROM hoja_vida WHERE id_usuario = ?", [id_usuario]);
    if (cv.length === 0) {
      return res.status(400).json({ message: "Debes crear tu hoja de vida antes de poder postularte." });
    }

    await conexion.query("INSERT INTO postulaciones (id_usuario, id_vacante) VALUES (?, ?)", [id_usuario, id_vacante]);
    res.status(201).json({ message: "¡Postulación exitosa!" });
  } catch (error) {
    if (error.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({ message: "Ya te has postulado a esta vacante." });
    }
    console.error("Error al postularse a la vacante:", error);
    res.status(500).json({ message: "Error en el servidor al procesar la postulación." });
  }
});

// me llama las postulaciones hechas por el usuario
app.get("/api/my-applications", verifyToken, async (req, res) => {
  const id_usuario = req.user.userId;
  try {
    const [applications] = await conexion.query(
      `SELECT 
        p.estado, 
        p.fecha_postulacion, 
        v.id_vacante,
        v.titulo AS vacante_titulo,
        admin.nombres AS admin_nombre,
        admin.apellidos AS admin_apellidos
       FROM postulaciones p
       JOIN vacantes v ON p.id_vacante = v.id_vacante
       LEFT JOIN usuarios admin ON p.id_admin_revisor = admin.id_usuario
       WHERE p.id_usuario = ?
       ORDER BY p.fecha_postulacion DESC`,
      [id_usuario]
    );
    res.status(200).json(applications);
  } catch (error) {
    console.error("Error al obtener mis postulaciones:", error);
    res.status(500).json({ message: "Error en el servidor." });
  }
});
// area de administración para manejar las postulaciones
// permite al admin actualizar el estado de una postulación
app.post("/api/admin/applications/:id/status", [verifyToken, verifyRole(['administrador', 'superusuario'])], async (req, res) => {
  const { id: id_postulacion } = req.params;
  const { estado } = req.body;
  const id_admin = req.user.userId; // muestra el admin que está haciendo el cambio

  if (!estado || !['en revisión', 'aceptado', 'rechazado'].includes(estado)) {
    return res.status(400).json({ message: "Estado no válido." });
  }

  try {
    await conexion.query("UPDATE postulaciones SET estado = ?, id_admin_revisor = ? WHERE id_postulacion = ?", [estado, id_admin, id_postulacion]);
    res.status(200).json({ message: `Postulación actualizada a '${estado}'.` });
  } catch (error) {
    console.error("Error al actualizar la postulación:", error);
    res.status(500).json({ message: "Error en el servidor." });
  }
});

// llama todas las postulaciones que hay para la vacante
app.get("/api/admin/applications", [verifyToken, verifyRole(['administrador', 'superusuario'])], async (req, res) => {
  try {
    const [applications] = await conexion.query(`
      SELECT 
        p.id_postulacion,
        p.estado,
        p.fecha_postulacion,
        u.id_usuario,
        u.nombres AS usuario_nombres,
        u.apellidos AS usuario_apellidos,
        v.id_vacante,
        v.titulo AS vacante_titulo
      FROM postulaciones p
      JOIN usuarios u ON p.id_usuario = u.id_usuario
      JOIN vacantes v ON p.id_vacante = v.id_vacante
      ORDER BY v.fecha_creacion DESC, p.fecha_postulacion DESC
    `);
    res.status(200).json(applications);
  } catch (error) {
    console.error("Error al obtener todas las postulaciones:", error);
    res.status(500).json({ message: "Error en el servidor." });
  }
});
// area super usuario y manejo de usuarios
//crear un nuevo usuario
app.post("/api/super/create-user", [verifyToken, verifyRole(['superusuario'])], async (req, res) => {
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

// me llama a todos los admin
app.get("/api/super/admins", [verifyToken, verifyRole(['superusuario'])], async (req, res) => {
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

// eliminar un usuario
app.delete("/api/super/user/:userId", [verifyToken, verifyRole(['superusuario'])], async (req, res) => {
  const { userId } = req.params;
  try {
    // validacion para el super no elimine su propio perfil
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

// me llamq a todos los usuarios 
app.get("/api/super/users", [verifyToken, verifyRole(['superusuario'])], async (req, res) => {
  try {
    const [users] = await conexion.query(`
      SELECT u.id_usuario, u.nombres, u.apellidos, u.correo, r.nombre_rol
      FROM usuarios u
      JOIN roles r ON u.id_rol = r.id_rol
      ORDER BY u.id_rol, u.nombres
    `);
    res.status(200).json(users);
  } catch (error) {
    console.error("Error al obtener todos los usuarios para gestión:", error);
    res.status(500).json({ message: "Error en el servidor." });
  }
});

// me llama las estaisticas generales
app.get("/api/super/stats", [verifyToken, verifyRole(['superusuario'])], async (req, res) => {
  try {
    const [totalUsers] = await conexion.query("SELECT COUNT(*) as count FROM usuarios");
    const [totalAdmins] = await conexion.query("SELECT COUNT(*) as count FROM usuarios WHERE id_rol = 2");
    const [totalVacancies] = await conexion.query("SELECT COUNT(*) as count FROM vacantes");
    const [totalApplications] = await conexion.query("SELECT COUNT(*) as count FROM postulaciones");

    const stats = {
      users: totalUsers[0].count,
      admins: totalAdmins[0].count,
      vacancies: totalVacancies[0].count,
      applications: totalApplications[0].count,
    };

    res.status(200).json(stats);

  } catch (error) {
    console.error("Error al obtener las estadísticas:", error);
    res.status(500).json({ message: "Error en el servidor." });
  }
});

// me deja ver todos los usuarios y sus postulaciones
app.get("/api/super/all-users", [verifyToken, verifyRole(['superusuario'])], async (req, res) => {
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

// inicio el servidor
app.listen(port, () => {
  console.log(`🚀 Servidor escuchando en http://localhost:${port}`);
});