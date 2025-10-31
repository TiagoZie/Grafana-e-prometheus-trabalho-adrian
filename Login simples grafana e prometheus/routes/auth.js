// routes/auth.js
const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../models/User');

// Rota de Registro
router.post('/register', async (req, res) => {
    try {
        const { username, password } = req.body;

        // Verifica se o usuário já existe
        let user = await User.findOne({ username });
        if (user) {
            return res.status(400).json({ msg: 'Usuário já existe' });
        }

        // Cria um novo usuário
        user = new User({
            username,
            password
        });

        // Criptografa a senha
        const salt = await bcrypt.genSalt(10);
        user.password = await bcrypt.hash(password, salt);

        // Salva o usuário no banco de dados
        await user.save();

        res.status(201).send('Usuário registrado com sucesso!');

    } catch (err) {
        console.error(err.message);
        res.status(500).send('Erro no servidor');
    }
});

// Rota de Login
router.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        // Verifica se o usuário existe
        const user = await User.findOne({ username });
        if (!user) {
            return res.status(400).json({ msg: 'Credenciais inválidas' });
        }

        // Compara as senhas
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ msg: 'Credenciais inválidas' });
        }

        // Cria e retorna o token JWT
        const payload = {
            user: {
                id: user.id
            }
        };

        jwt.sign(
            payload,
            process.env.JWT_SECRET,
            { expiresIn: 3600 }, // Expira em 1 hora
            (err, token) => {
                if (err) throw err;
                res.json({ token });
            }
        );

    } catch (err) {
        console.error(err.message);
        res.status(500).send('Erro no servidor');
    }
});

module.exports = router;