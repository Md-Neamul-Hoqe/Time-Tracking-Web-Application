const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
require('dotenv').config()
const express = require('express');
const cors = require('cors');
const jsonwebtoken = require('jsonwebtoken');
const cookieParser = require('cookie-parser');

const port = process.env.PORT || 5000;

const app = express();


app.use(cors({
    origin: [ "http://localhost:5173" ],
    credentials: true
}));
app.use(express.static("public"));
app.use(express.json());
app.use(cookieParser());

const client = new MongoClient(process.env.URI, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    }
});

async function run() {
    try {
        const db = client.db(process.env.DB_NAME);
        const userCollection = db.collection('users');

        /**
         * =======================================================
         * AUTH API
         * =======================================================
         */

        /* Middleware JWT implementation */

        const verifyToken = async (req, res, next) => {
            try {
                // console.log('the token to be verified: ', req?.cookies);
                const token = req?.cookies?.[ "posetDb-token" ];


                if (!token) return res.status(401).send({ message: 'Unauthorized access' })

                jsonwebtoken.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
                    // console.log(err);
                    if (err) {
                        // console.log(err);
                        return res.status(401).send({ message: 'You are not authorized' })
                    }

                    // console.log(decoded);
                    req.user = decoded;
                    next();
                })
            } catch (error) {
                // console.log(error);
                res.status(500).send({ message: error?.message || error?.errorText });
            }
        }

        /* verify admin after verify token */
        const verifyAdmin = async (req, res, next) => {
            const { email } = req?.user;
            // console.log(email);
            const query = { email }

            const theUser = await userCollection.findOne(query)
            //console.log('isAdmin : ', theUser);

            const isAdmin = theUser?.role === 'admin'
            if (!isAdmin) res.status(403).send({ message: 'Access Forbidden' })

            next();
        }

        // console.log(process.env);
        const setTokenCookie = async (req, res, next) => {
            const user = req?.body;

            // console.log(user);

            if (user?.email) {
                const token = jsonwebtoken.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '24h' })

                // console.log('Token generated: ', token);
                res
                    .cookie('posetDb-token', token, {
                        httpOnly: true,
                        secure: true,
                        sameSite: "none",
                    })
                req[ "posetDb-token" ] = token;
                // console.log(req[ "posetDb-token" ]);
                next();
            }
        }

        /* Create JWT */
        app.post('/api/v2/auth/jwt', setTokenCookie, (req, res) => {
            try {
                const token = req[ "posetDb-token" ];

                // console.log('The user: ', user);
                // console.log('token in cookie: ', token);

                if (!token) return res.status(400).send({ success: false, message: 'Unknown error occurred' })

                //console.log('User sign in successfully.');
                res.send({ success: true })
            } catch (error) {
                res.status(500).send({ error: true, message: error.message })
            }

        })

        /**
         * ==============================================
         * USERS API
         * ==============================================
         */
        /* clear cookie / token of logout user */
        app.post('/api/v2/user/logout', (_req, res) => {
            try {
                //console.log('User log out successfully.');

                res.clearCookie('posetDb-token', { maxAge: 0 }).send({ success: true })
            } catch (error) {
                res.status(500).send({ error: true, message: error.message })
            }
        })

    } catch (error) {
        console.log(error);
    }
}
run().catch(console.dir);





app.get('/', (_req, res) => {
    res.send('Poset Database App is running');
})

app.listen(port, () => {
    console.log(`Poset server is running on ${port}`);
})