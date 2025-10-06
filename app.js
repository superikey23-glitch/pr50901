const express = require('express');
const { Sequelize, DataTypes } = require('sequelize');
const path = require('path');
const bodyParser = require('body-parser');
const session = require('express-session');
const bcrypt = require('bcrypt');

const app = express();
const PORT = 3000;

app.use(bodyParser.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, 'public')));

app.use(session({
    secret: 'your-secret-key',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false } 
}));

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.get('/catalog', (req, res) => {
    res.render('catalog');
});

app.get('/cart', (req, res) => {
    res.render('cart');
});



const sequelize = new Sequelize({
    dialect: 'sqlite',
    storage: 'database.sqlite',
});

const Product = sequelize.define('Product', {
    name: { type: DataTypes.STRING, allowNull: false },
    price: { type: DataTypes.FLOAT, allowNull: false },
});

const Category = sequelize.define('Category', {
    name: { type: DataTypes.STRING, allowNull: false },
});

const Supplier = sequelize.define('Supplier', {
    name: { type: DataTypes.STRING, allowNull: false },
    contact: { type: DataTypes.STRING },
});

const User = sequelize.define('User', {
    username: { 
        type: DataTypes.STRING, 
        allowNull: false,
        unique: true
    },
    password: { 
        type: DataTypes.STRING, 
        allowNull: false 
    },
    role: { 
        type: DataTypes.ENUM('user', 'manager', 'admin'),
        defaultValue: 'user'
    }
});

Product.belongsTo(Category);
Product.belongsTo(Supplier);
Category.hasMany(Product);
Supplier.hasMany(Product);

const requireAuth = (req, res, next) => {
    if (!req.session.user) {
        return res.redirect('/login');
    }
    next();
};

const requireRole = (roles) => {
    return (req, res, next) => {
        if (!req.session.user) {
            return res.redirect('/login');
        }
        if (!roles.includes(req.session.user.role)) {
            return res.status(403).send('Доступ запрещен');
        }
        next();
    };
};

app.get('/', async (req, res) => {
    try {
        const products = await Product.findAll({
            include: [Category, Supplier],
        });
        res.render('index', { 
            products,
            user: req.session.user 
        });
    } catch (error) {
        console.error('Ошибка при получении продуктов:', error);
        res.status(500).send('Внутренняя ошибка сервера');
    }
});

app.get('/login', (req, res) => {
    res.render('login', { error: null });
});

app.get('/register', (req, res) => {
    res.render('register', { error: null });
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});

app.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const user = await User.findOne({ where: { username } });
        
        if (user && await bcrypt.compare(password, user.password)) {
            req.session.user = {
                id: user.id,
                username: user.username,
                role: user.role
            };
            res.redirect('/');
        } else {
            res.render('login', { error: 'Неверные учетные данные' });
        }
    } catch (error) {
        console.error('Ошибка при входе:', error);
        res.render('login', { error: 'Ошибка сервера' });
    }
});

app.post('/register', async (req, res) => {
    try {
        const { username, password, confirmPassword } = req.body;
        
        if (password !== confirmPassword) {
            return res.render('register', { error: 'Пароли не совпадают' });
        }
        
        const existingUser = await User.findOne({ where: { username } });
        if (existingUser) {
            return res.render('register', { error: 'Пользователь уже существует' });
        }
        
        const hashedPassword = await bcrypt.hash(password, 10);
        await User.create({
            username,
            password: hashedPassword,
            role: 'user'
        });
        
        res.redirect('/login');
    } catch (error) {
        console.error('Ошибка при регистрации:', error);
        res.render('register', { error: 'Ошибка сервера' });
    }
});

app.get('/add-category', requireAuth, requireRole(['admin', 'manager']), (req, res) => {
    res.render('add-category', { user: req.session.user });
});

app.get('/add-supplier', requireAuth, requireRole(['admin', 'manager']), (req, res) => {
    res.render('add-supplier', { user: req.session.user });
});

app.get('/add-product', requireAuth, requireRole(['admin', 'manager']), async (req, res) => {
    try {
        const categories = await Category.findAll();
        const suppliers = await Supplier.findAll();
        res.render('add-product', { 
            categories, 
            suppliers,
            user: req.session.user 
        });
    } catch (error) {
        console.error('Ошибка при получении категорий или поставщиков:', error);
        res.status(500).send('Внутренняя ошибка сервера');
    }
});

app.get('/edit-product/:id', requireAuth, requireRole(['admin', 'manager']), async (req, res) => {
    try {
        const productId = req.params.id;
        const product = await Product.findByPk(productId, {
            include: [Category, Supplier],
        });
        const categories = await Category.findAll();
        const suppliers = await Supplier.findAll();
        res.render('edit-product', { 
            product, 
            categories, 
            suppliers,
            user: req.session.user 
        });
    } catch (error) {
        console.error('Ошибка при получении продукта для редактирования:', error);
        res.status(500).send('Внутренняя ошибка сервера');
    }
});

app.post('/add-category', requireAuth, requireRole(['admin', 'manager']), async (req, res) => {
    try {
        const { name } = req.body;
        if (name) {
            await Category.create({ name });
        }
        res.redirect('/');
    } catch (error) {
        console.error('Ошибка при добавлении категории:', error);
        res.status(500).send('Внутренняя ошибка сервера');
    }
});

app.post('/add-supplier', requireAuth, requireRole(['admin', 'manager']), async (req, res) => {
    try {
        const { name, contact } = req.body;
        if (name) {
            await Supplier.create({ name, contact });
        }
        res.redirect('/');
    } catch (error) {
        console.error('Ошибка при добавлении поставщика:', error);
        res.status(500).send('Внутренняя ошибка сервера');
    }
});

app.post('/add-product', requireAuth, requireRole(['admin', 'manager']), async (req, res) => {
    try {
        const { name, price, categoryId, supplierId } = req.body;

        if (name && price && categoryId && supplierId) {
            await Product.create({ 
                name, 
                price, 
                CategoryId: categoryId, 
                SupplierId: supplierId 
            });
            res.redirect('/');
        } else {
            res.status(400).send('Все поля обязательны для заполнения');
        }
    } catch (error) {
        console.error('Ошибка при добавлении продукта:', error);
        res.status(500).send('Внутренняя ошибка сервера');
    }
});

app.post('/delete-product/:id', requireAuth, requireRole(['admin']), async (req, res) => {
    try {
        const productId = req.params.id;
        await Product.destroy({
            where: { id: productId },
        });
        res.redirect('/');
    } catch (error) {
        console.error('Ошибка при удалении продукта:', error);
        res.status(500).send('Внутренняя ошибка сервера');
    }
});

app.post('/edit-product/:id', requireAuth, requireRole(['admin', 'manager']), async (req, res) => {
    try {
        const productId = req.params.id;
        const { name, price, categoryId, supplierId } = req.body;

        await Product.update(
            { name, price, CategoryId: categoryId, SupplierId: supplierId },
            { where: { id: productId } }
        );
        res.redirect('/');
    } catch (error) {
        console.error('Ошибка при обновлении продукта:', error);
        res.status(500).send('Внутренняя ошибка сервера');
    }
});

app.use((req, res, next) => {
    res.status(404).render('404');
});

(async () => {
    try {
        await sequelize.sync({force:true}); 

        const category1 = await Category.create({ name: 'Электроника' });
        const category2 = await Category.create({ name: 'Книги' });
        const category3 = await Category.create({ name: 'Хозтовары' });

        const supplier1 = await Supplier.create({ 
            name: 'TechCorp', 
            contact: 'techcorp@example.com' 
        });
        const supplier2 = await Supplier.create({ 
            name: 'BookStore', 
            contact: 'contact@bookstore.com' 
        });
        const supplier3 = await Supplier.create({ 
            name: 'HomeGoods', 
            contact: 'info@homegoods.com' 
        });

        await Product.create({ 
            name: 'Ноутбук', 
            price: 1200.99, 
            CategoryId: category1.id, 
            SupplierId: supplier1.id 
        });

        await Product.create({ 
            name: 'Смартфон', 
            price: 799.49, 
            CategoryId: category1.id, 
            SupplierId: supplier1.id 
        });

        await Product.create({ 
            name: 'Книга по программированию', 
            price: 29.99, 
            CategoryId: category2.id, 
            SupplierId: supplier2.id 
        });
        
        await Product.create({ 
            name: 'Ведро пластиковое', 
            price: 6.99, 
            CategoryId: category3.id, 
            SupplierId: supplier3.id 
        });
        
        await Product.create({ 
            name: 'Книга про веники', 
            price: 2.99, 
            CategoryId: category2.id, 
            SupplierId: supplier2.id 
        });
        
        await Product.create({ 
            name: 'Мыло', 
            price: 45000.00, 
            CategoryId: category3.id, 
            SupplierId: supplier3.id 
        });

        const hashedAdminPassword = await bcrypt.hash('admin123', 10);
        const hashedManagerPassword = await bcrypt.hash('manager123', 10);
        const hashedUserPassword = await bcrypt.hash('user123', 10);

        await User.create({
            username: 'admin',
            password: hashedAdminPassword,
            role: 'admin'
        });

        await User.create({
            username: 'manager',
            password: hashedManagerPassword,
            role: 'manager'
        });

        await User.create({
            username: 'user',
            password: hashedUserPassword,
            role: 'user'
        });

        console.log('База данных синхронизирована и тестовые данные созданы!');
        console.log('Тестовые пользователи:');
        console.log('Админ - login: admin, password: admin123');
        console.log('Менеджер - login: manager, password: manager123');
        console.log('Пользователь - login: user, password: user123');
        
        app.listen(PORT, () => {
            console.log(`Сервер запущен на http://localhost:${PORT}`);
        });
    } catch (error) {
        console.error('Ошибка при инициализации приложения:', error);
    }
})();