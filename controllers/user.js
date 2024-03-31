// Importar dependencias y módulos
const bcrypt = require('bcrypt');
const mongoosePagination = require('mongoose-pagination');
const fs = require('fs');

// Importar modelos
const User = require("../models/user");

// Importar servicios 
const jwt = require("../services/jwt");

// Acciones de prueba 
const pruebaUser = (req, res) => {
    return res.status(200).send({
        message: "Mensaje enviado desde el controlador controllers/user.js",
        usuario: req.user
    });
}

const register = async (req, res) => {
    // Recoger datos de la petición
    let params = req.body;

    // Comprobar que se reciben los datos necesarios (+ validación)
    if (!params.name || !params.email || !params.password || !params.nick) {
        return res.status(400).send({
            status: "error",
            message: "Faltan datos para el registro"
        });
    }

    try {
        // Control de usuarios duplicados
        const users = await User.find({ 
            $or: [
                {email: params.email.toLowerCase()},
                {nick: params.nick.toLowerCase()}
            ]
        }).exec(); // Usando exec() aquí para convertirlo en una promesa

        if (users.length >= 1) {
            return res.status(200).send({
                status: "success",
                message: "El usuario ya existe"
            });
        } else {
            // Cifrar la contraseña
            const pwd = await bcrypt.hash(params.password, 10);
            params.password = pwd;

            // Crear objeto de usuario
            let user_to_save = new User(params);

            // Guardar usuario en la bd
            const userStored = await user_to_save.save();

            // Devolver resultado
            return res.status(200).send({
                status: "success",
                message: "Usuario registrado correctamente",
                user: userStored
            });
        }
    } catch (error) {
        return res.status(500).send({
            status: "error",
            message: "Error en la operación",
            error: error.message
        });
    }
};

const login = async (req, res) => {
    try {
        // Recoger parámetros del body
        const params = req.body;

        if (!params.email || !params.password) {
            return res.status(400).send({
                status: "error",
                message: "Faltan datos por enviar"
            });
        }

        // Buscar en la bd si existe el usuario
        const user = await User.findOne({ email: params.email }).select({ password: 1, name: 1, nick: 1, id: 1 }).exec();

        if (!user) {
            return res.status(404).send({
                status: "error",
                message: "No existe el usuario"
            });
        }

        // Comprobar su contraseña
        const pwd = bcrypt.compareSync(params.password, user.password);

        if (!pwd) {
            return res.status(400).send({
                status: "error",
                message: "La contraseña no es correcta"
            });
        }

        // Conseguir token
        const token = jwt.createToken(user);

        // Devolver datos del usuario
        return res.status(200).send({
            status: "success",
            message: "Acción de login",
            user: {
                id: user.id,
                name: user.name,
                nick: user.nick,
            },
            token
        });
    } catch (error) {
        console.log(error);
        return res.status(500).send({
            status: "error",
            message: "Error en el servidor"
        });
    }
};

const profile = async (req, res) => {
    try {
        // Recibir el parámetro del id de usuario por la URL
        const id = req.params.id;

        const userProfile = await User.findById(id).select({password: 0, role: 0}).exec();

        // Verificar si se encontró el perfil del usuario
        if (!userProfile) {
            return res.status(404).send({
                status: "error",
                message: "El usuario no existe"
            });
        }

        // Devolver el resultado
        // Posteriormente: devolver información de follows 
        return res.status(200).send({
            status: "success",
            user: userProfile
        });

    } catch (error) {
        return res.status(500).send({
            status: "error",
            message: "Error al buscar el usuario"
        });
    }
}

const list = async (req, res) => {
    try {
        // Controlar en qué página estamos
        let page = parseInt(req.params.page) || 1;
        let itemsPerPage = 2;

        const users = await User.find().sort('_id').paginate(page, itemsPerPage);
        const total = await User.countDocuments(); 

        if (!users.length) {
            return res.status(404).send({
                status: "error",
                message: "No hay usuarios disponibles"
            });
        }

        // Devolver el resultado
        return res.status(200).send({
            status: "success",
            users,
            page,
            itemsPerPage,
            total,
            pages: Math.ceil(total / itemsPerPage)
        });
    } catch (error) {
        return res.status(500).send({
            status: "error",
            message: "Error en la petición"
        });
    }
};

const update = async (req, res) => {
    // Recoger info del usuario a actualizar
    let userIdentity = req.user;
    let userToUpdate = req.body;

    // Eliminar los campos sobrantes
    delete userToUpdate.iat;
    delete userToUpdate.exp;
    delete userToUpdate.role;
    delete userToUpdate.image;

    // Comprobar si el usuario ya existe
    try {
        // Control de usuarios duplicados
        const users = await User.find({ 
            $or: [
                {email: userToUpdate.email.toLowerCase()},
                {nick: userToUpdate.nick.toLowerCase()}
            ]
        }).exec(); // Usando exec() aquí para convertirlo en una promesa

        let userIsset = false;
        users.forEach(user => {
            if (user && user._id != userIdentity.id) userIsset = true;
        });

        if (userIsset) {
            return res.status(200).send({
                status: "success",
                message: "El usuario ya existe"
            });
        } else {
            // Cifrar la contraseña
            if (userToUpdate.password) {
                const pwd = await bcrypt.hash(userToUpdate.password, 10);
                userToUpdate.password = pwd;
            }

            // Buscar y actualizar
            const userUpdated = await User.findByIdAndUpdate(userIdentity.id, userToUpdate, { new: true }).exec();

            if (!userUpdated) {
                return res.status(400).send({
                    status: "error",
                    message: "No se encontró el usuario para actualizar"
                });
            }

            // Devolver la respuesta
            return res.status(200).send({
                status: "success",
                message: "Usuario actualizado correctamente",
                user: userUpdated
            });
        }
    } catch (error) {
        return res.status(500).send({
            status: "error",
            message: "Error en la operación"
        });
    }
};

const upload = (req, res) => {
    // Recoger el fichero de imagen y comprobar que existe
    if(!req.file) {
        return res.status(404).send({
            status: "error",
            message: "Petición no incluye la imagen"
        });
    }

    // Conseguir el nombre del archivo 
    let image = req.file.originalname;

    // Sacar la extensión del archivo
    const imageSplit = image.split("\.");
    const extension = imageSplit[1];

    // Comprobar extensión
    if (extension != "png" && extension != "jpg" && extension != "jpeg" && extension != "gif") {
        // Borrar archivo subido
        const filePath = req.file.path;
        const fileDeleted = fs.unlinkSync(filePath);

        // Devolver respuesta negativa
        return res.status(404).send({
            status: "error",
            message: "Extensión del fichero inválida"
        });
    }

    // Si no es correcta, borrar archivo
    
    // Si es correcta, guardar imagen en la BD

    // Devolver respuesta
    return res.status(200).send({
        status: "success",
        message: "Subida de imágenes",
        user: req.user,
        file: req.file,
        files: req.files
    });
};

// Exportar acciones
module.exports = {
    pruebaUser,
    register,
    login,
    profile,
    list,
    update,
    upload
}