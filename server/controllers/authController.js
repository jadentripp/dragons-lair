const bcrypt = require('bcryptjs')

module.exports = {
    register: async (req, res) => {
        const {username, password, isAdmin} = req.body;
        const db = req.app.get('db');
        const foundUser  =  await db.get_user(username);
        const existingUser = foundUser[0];
        if (existingUser){
            return res.status(409).send('Username Taken')
        }
        else{
            const salt = bcrypt.genSaltSync(10)
            const hash = bcrypt.hashSync(password, salt)
            const registeredUser = await db.register_user(isAdmin, username, hash)
            const user = registeredUser[0]
            req.session.user = {
                isAdmin: user.is_admin,
                id: user.id,
                username: user.username
            }
            res.status(201).send(user)
        }
    },
    login: async (req, res) => {
        const {username, password} = req.body
        const db = req.app.get('db')
        const foundUser = await db.get_user([username]);
        const user = foundUser[0];
        const isAuthenticated = bcrypt.compareSync(password, user.hash);
        if (!user){
           return res.status(401).send('User not found')
        }
        if(isAuthenticated===false){
           return res.status(403).send('Incorrect password')
        }
        else{
            req.session.user = {
                isAdmin: user.is_admin,
                id: user.id,
                username: user.username
            }
           return req.session.user.sendStatus(200)
        }
    },
    logout: async (req, res) => {
        req.session.destroy()
        res.sendStatus(200)
    },
}