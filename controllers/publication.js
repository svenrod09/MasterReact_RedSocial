
// Acciones de prueba 
const pruebaPublication = (req, res) => {
    return res.status(200).send({
        message: "Mensaje enviado desde el controlador controllers/publication.js"
    });
}

// Exportar acciones
module.exports = {
    pruebaPublication
}