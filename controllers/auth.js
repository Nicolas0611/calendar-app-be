const express = require("express");
const bcrypt = require("bcryptjs");
const { validationResult } = require("express-validator");
const Usuario = require("../models/Usuario");
const { generarJWT } = require("../helpers/jwt");

const crearUsuario = async (req, res = express.response) => {
  const { email, password } = req.body;

  try {
    //Se valida que el usuario ya existe, si existe entonces se manda un error 400
    let usuario = await Usuario.findOne({ email });
    if (usuario) {
      return res.status(400).json({
        ok: false,
        msg: "Un usuario ya existe con ese correo",
      });
    }
    //Se guarda el usuario en la BD
    usuario = new Usuario(req.body);

    // Encriptar contrseña
    const salt = bcrypt.genSaltSync();
    usuario.password = bcrypt.hashSync(password, salt);

    await usuario.save();

    //Generar un JWT
    const token = await generarJWT(usuario.id, usuario.name);

    // Status succesfull
    res.status(201).json({
      ok: true,
      uid: usuario.id,
      name: usuario.name,
      token,
    });
  } catch (error) {
    //Error en la conexion de la base de Datos
    console.log(error);
    res.status(500).json({
      ok: false,
      msg: "Porfavor hable con el admin",
    });
  }
};

const loginUsuario = async (req, res = express.response) => {
  //Coger el email y password de la request
  const { email, password } = req.body;
  try {
    // buscar un usuario con el email de la request
    const usuario = await Usuario.findOne({ email });

    //Si no existe el usuario entonces mandar una response 400
    if (!usuario) {
      return res.status(400).json({
        ok: false,
        msg: "El usuario no existe con ese email",
      });
    }
    // Comparar contraseña ( Devuelve valor booleano true, false)
    const validPassword = bcrypt.compareSync(password, usuario.password);

    //Si la contraseña no es valida mandar error 400
    if (!validPassword) {
      return res.status(400).json({
        ok: false,
        msg: "La contraseña no es valida",
      });
    }

    //Generar un JWT
    const token = await generarJWT(usuario.id, usuario.name);

    res.status(201).json({
      ok: true,
      uid: usuario.id,
      name: usuario.name,
      token,
    });
  } catch (error) {
    //Error en la conexion de la base de Datos
    console.log(error);
    res.status(500).json({
      ok: false,
      msg: "Porfavor hable con el admin",
    });
  }
};

const revalidarToken = async (req, res = express.response) => {
  const uid = req.uid;
  const name = req.name;

  // generar un nuevo JWT y retornarlo en la peticion
  const token = await generarJWT(uid, name);
  res.json({
    ok: true,
    uid,
    name,
    token,
  });
};

module.exports = {
  crearUsuario,
  loginUsuario,
  revalidarToken,
};
