const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const client = require('prom-client');
require('dotenv').config();

const User = require('./models/User');
console.log('AAAAAAAAAAAAAAAAAAAAAAAAA');
const app = express();
const PORT = process.env.PORT || 3000;
// Métricas padrão segundo o chatgpt
const collectDefaultMetrics = client.collectDefaultMetrics;
collectDefaultMetrics({ prefix: 'app_' }); // adiciona um prefixo para organizar melhor

// Métrica original da aula
const totalRequestsCounter = new client.Counter({
    name: 'total_requests',
    help: 'Contador de requisições totais'
});

// conta quantos registros ocorreram 
const userRegistrationsCounter = new client.Counter({
    name: 'app_user_registrations_total',
    help: 'Contador de registros de usuários bem-sucedidos'
});
// conta quantos logins ocorreram 
const userLoginsCounter = new client.Counter({
    name: 'app_user_logins_total',
    help: 'Contador de logins bem-sucedidos'
});
// demora da request
const httpRequestDurationMicroseconds = new client.Histogram({
    name: 'app_http_request_duration_seconds',
    help: 'Duração das requisições HTTP em segundos',
    labelNames: ['method', 'route', 'code'],
    buckets: [0.1, 0.3, 0.5, 0.7, 1, 3, 5, 7, 10] // Buckets em segundos
});

// middlewares
app.set('view engine', 'ejs'); // estou usando EJS para as páginas, só para mudar um pouco
app.use(express.static('public')); // Serve arquivos estáticos da pasta 'public'
app.use(bodyParser.urlencoded({ extended: true })); // Para analisar o corpo de formulários HTML
app.use(cookieParser());
app.use(session({
    secret: process.env.JWT_SECRET, // Reutilizando a variável de ambiente
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false } // Em produção, use 'true' com HTTPS
}));

// MONGO PORQUE O POSTGRES NÃO FUNCIONA NO MEU NOTEBOOK
mongoose.connect(process.env.MONGO_URI).then(() => {
    console.log('Conectado ao MongoDB');
}).catch(err => {
    console.error('Erro ao conectar ao MongoDB', err);
});


// --- Rotas de Renderização de Páginas ---

// Rota principal - redireciona para o login se não estiver logado
app.get('/', (req, res) => {
    if (req.session.userId) {
        res.redirect('/dashboard');
    } else {
        res.redirect('/login');
    }
});
app.use((req, res, next) => {
    const end = httpRequestDurationMicroseconds.startTimer();
    totalRequestsCounter.inc(); // Incrementa o contador ORINGINAL

    res.on('finish', () => {
        end({ 
            method: req.method, 
            route: req.path, 
            code: res.statusCode 
        });
    });
    next();
});
app.get('/login', (req, res) => {
    res.render('login', { error: null }); // Renderiza login.ejs
});

app.get('/register', (req, res) => {
    res.render('register', { error: null }); // Renderiza register.ejs
});

// Rota do dashboard - protegida
app.get('/dashboard', (req, res) => {
    if (!req.session.userId) {
        return res.redirect('/login');
    }
    // Supondo que você armazenou o username na sessão ao fazer login
    res.render('dashboard', { username: req.session.username });
});


// --- Rotas de Lógica de Autenticação ---

// Rota de Registro (POST)
app.post('/register', async (req, res) => {
    try {
        const { username, password } = req.body;
        let user = await User.findOne({ username });
        if (user) {
            return res.render('register', { error: 'Usuário já existe.' });
        }

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        user = new User({ username, password: hashedPassword });
        await user.save();
        console.log('REGISTRO!!!!!!!!');
        userRegistrationsCounter.inc();
        res.redirect('/login');
    } catch (err) {
        res.render('register', { error: 'Erro ao registrar. Tente novamente.' });
    }
});

// Rota de Login (POST)
app.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const user = await User.findOne({ username });
        if (!user) {
            return res.render('login', { error: 'Credenciais inválidas.' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.render('login', { error: 'Credenciais inválidas.' });
        }
        
        // Configura a sessão do usuário
        req.session.userId = user._id;
        req.session.username = user.username;

        console.log('LOGIN!!!!!!!!!!');
        userLoginsCounter.inc();

        res.redirect('/dashboard');
    } catch (err) {
        res.render('login', { error: 'Erro no servidor. Tente novamente.' });
    }
});

// Rota de Logout
app.get('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            return res.redirect('/dashboard');
        }
        res.clearCookie('connect.sid'); // Limpa o cookie da sessão
        res.redirect('/login');
    });
});
app.get('/metrics', async (req, res) => {
    res.set('Content-Type', client.register.contentType);
    res.end(await client.register.metrics());
});

// --- Iniciar o Servidor ---
app.listen(PORT, () => {
    console.log(`Servidor rodando na porta ${PORT}`);
});